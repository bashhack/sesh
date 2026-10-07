package main

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"text/tabwriter"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/vault"
)

// folderCommands and tagCommands are what follows sesh folder and sesh tag.
var (
	folderCommands = []candidate{
		{"move", "Put entries in a folder (\"\" takes them out)"},
		{"rename", "Rename a folder, and the folders under it"},
		{"list", "Show the folders, with how many entries each holds"},
	}
	tagCommands = []candidate{
		{"add", "Tag entries"},
		{"remove", "Take a tag off entries"},
		{"rename", "Rename a tag on every entry"},
		{"list", "Show the tags, with how many entries have each"},
	}
)

const folderUsage = `Usage:
  sesh folder move <folder> <id>…     Put entries in a folder, such as work/aws ("" takes them out)
  sesh folder rename <old> <new>      Rename a folder, and the folders under it
  sesh folder list                    Show the folders, with how many entries each holds

Entry IDs are what --list shows. Folders nest with "/".`

const tagUsage = `Usage:
  sesh tag add <tag> <id>…            Tag entries
  sesh tag remove <tag> <id>…         Take a tag off entries
  sesh tag rename <old> <new>         Rename a tag on every entry
  sesh tag list                       Show the tags, with how many entries have each

Entry IDs are what --list shows.`

// runFolder is sesh folder: move, rename, list.
func runFolder(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, folderUsage)
		return err
	}
	switch args[0] {
	case "move":
		if len(args) < 3 {
			return errors.New(`sesh folder move needs a folder and at least one entry ID: sesh folder move <folder> <id>… ("" for no folder)`)
		}
		folder := args[1]
		if err := vault.CheckFolder(folder); err != nil {
			return err
		}
		return changeEntries(app, args[2:], func(s *database.Store, keys []vault.Key) (string, error) {
			n, err := s.MoveToFolder(keys, folder)
			if err != nil {
				return "", err
			}
			if folder == "" {
				their := "their folders"
				if n == 1 {
					their = "its folder"
				}
				return fmt.Sprintf("Took %s out of %s%s", entryCount(n), their, unchanged(len(keys)-n, "was in no folder", "were in no folder")), nil
			}
			return fmt.Sprintf("Moved %s to %s%s", entryCount(n), folder, unchanged(len(keys)-n, "was already there", "were already there")), nil
		})
	case "rename":
		if len(args) != 3 {
			return errors.New("sesh folder rename needs the folder and its new name: sesh folder rename <old> <new>")
		}
		from, to := args[1], args[2]
		return renameFiling(app, "folder", from, to, func(s *database.Store) (int, bool, error) { return s.RenameFolder(from, to) },
			&vault.Filter{Folder: from, FolderSet: true})
	case "list":
		if len(args) > 1 {
			return fmt.Errorf("sesh folder list takes no arguments, got %q", strings.Join(args[1:], " "))
		}
		return listFolders(app)
	}
	return fmt.Errorf("unknown sesh folder command %q: use move, rename, or list", args[0])
}

// runTag is sesh tag: add, remove, rename, list.
func runTag(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, tagUsage)
		return err
	}
	switch args[0] {
	case "add", "remove":
		if len(args) < 3 {
			return fmt.Errorf("sesh tag %s needs a tag and at least one entry ID: sesh tag %s <tag> <id>…", args[0], args[0])
		}
		tag := args[1]
		if err := vault.CheckTag(tag); err != nil {
			return err
		}
		if args[0] == "add" {
			return changeEntries(app, args[2:], func(s *database.Store, keys []vault.Key) (string, error) {
				n, err := s.AddTag(keys, tag)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("Tagged %s %s%s", entryCount(n), tag, unchanged(len(keys)-n, "already had it", "already had it")), nil
			})
		}
		return changeEntries(app, args[2:], func(s *database.Store, keys []vault.Key) (string, error) {
			n, err := s.RemoveTag(keys, tag)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("Took tag %s off %s%s", tag, entryCount(n), unchanged(len(keys)-n, "didn't have it", "didn't have it")), nil
		})
	case "rename":
		if len(args) != 3 {
			return errors.New("sesh tag rename needs the tag and its new name: sesh tag rename <old> <new>")
		}
		from, to := args[1], args[2]
		return renameFiling(app, "tag", from, to, func(s *database.Store) (int, bool, error) { return s.RenameTag(from, to) },
			&vault.Filter{Tags: []string{from}})
	case "list":
		if len(args) > 1 {
			return fmt.Errorf("sesh tag list takes no arguments, got %q", strings.Join(args[1:], " "))
		}
		return listTags(app)
	}
	return fmt.Errorf("unknown sesh tag command %q: use add, remove, rename, or list", args[0])
}

func isHelp(arg string) bool {
	return arg == "--help" || arg == "-help" || arg == "-h" || arg == "help"
}

// unchanged is " (1 was already there)" for the n entries named that a
// change left as they were; "" when there are none.
func unchanged(n int, one, many string) string {
	switch {
	case n <= 0:
		return ""
	case n == 1:
		return " (1 " + one + ")"
	}
	return fmt.Sprintf(" (%d %s)", n, many)
}

// changeEntries checks ids before unlocking (every one, so all the bad ones
// are reported together), then that each names an entry, and runs change
// on them all, or on none. It prints what change returns.
func changeEntries(app *App, ids []string, change func(*database.Store, []vault.Key) (string, error)) error {
	var keys []vault.Key
	var bad []string
	seen := map[vault.Key]bool{}
	for _, id := range ids {
		k, err := vault.ParseKey(id)
		if err != nil {
			bad = append(bad, err.Error())
			continue
		}
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	if err := nothingChanged(bad); err != nil {
		return err
	}
	store, err := openFilingStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	for _, k := range keys {
		if err := store.Exists(k); err != nil {
			if errors.Is(err, vault.ErrNotFound) {
				if h := password.CaseHint(store, k); h != "" {
					err = fmt.Errorf("%w; %s", err, h)
				}
			}
			bad = append(bad, err.Error())
		}
	}
	if err := nothingChanged(bad); err != nil {
		return err
	}
	msg, err := change(store, keys)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(app.Stdout, "✅ "+msg)
	return err
}

// nothingChanged is the error for the problems found, or nil for none.
func nothingChanged(problems []string) error {
	switch len(problems) {
	case 0:
		return nil
	case 1:
		return errors.New(problems[0])
	}
	return fmt.Errorf("nothing was changed:\n  %s", strings.Join(problems, "\n  "))
}

// renameFiling renames a folder or tag (what) with rename, after checking
// both names before unlocking. When from isn't on any entry, it says so,
// suggesting one that differs only by case (f is the filter for from).
func renameFiling(app *App, what, from, to string, rename func(*database.Store) (int, bool, error), f *vault.Filter) error {
	check := vault.CheckTag
	if what == "folder" {
		check = vault.CheckFolder
	}
	for _, name := range []string{from, to} {
		if err := check(name); err != nil {
			return err
		}
	}
	store, err := openFilingStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	n, merged, err := rename(store)
	if errors.Is(err, vault.ErrNotFound) {
		if hint := provider.NoMatchHint(store, f, ""); hint != "" {
			err = errors.New(hint)
		}
	}
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("✅ Renamed %s %s to %s, on %s", what, from, to, entryCount(n))
	if merged {
		msg += fmt.Sprintf("; %s was already in use, so the two are now one", to)
	}
	_, err = fmt.Fprintln(app.Stdout, msg)
	return err
}

// openFilingStore unlocks the vault, which must already exist.
func openFilingStore() (*database.Store, error) {
	cfg, err := settings()
	if err != nil {
		return nil, err
	}
	if err := requireVault(cfg.DBPath.Value, "there's no vault yet: create it first, by running any sesh command or sesh init"); err != nil {
		return nil, err
	}
	_, store, err := openAuditStore()
	return store, err
}

// listFolders prints the folder tree: each folder under its parent, with
// the entries in it, and in all when it has subfolders.
func listFolders(app *App) error {
	store, err := openFilingStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	folders, err := store.Folders()
	if err != nil {
		return err
	}
	var b strings.Builder
	unfiled := 0
	if len(folders) > 0 && folders[0].Name == "" {
		unfiled, folders = folders[0].Total, folders[1:]
	}
	if len(folders) == 0 {
		b.WriteString("No folders yet. File entries in one with: sesh folder move <folder> <id>…\n")
	} else {
		b.WriteString("Folders:\n")
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		for _, f := range folders {
			depth := strings.Count(f.Name, "/")
			own := ""
			if f.Entries > 0 {
				own = fmt.Sprint(f.Entries)
			}
			// The last column only when there's one, so no line ends in
			// spaces.
			all := ""
			if f.Total != f.Entries {
				all = fmt.Sprintf("\t(%d in all)", f.Total)
			}
			if _, err := fmt.Fprintf(tw, "  %s%s\t%s%s\n", strings.Repeat("  ", depth), path.Base(f.Name), own, all); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if unfiled > 0 {
		fmt.Fprintf(&b, "%s in no folder.\n", isAre(unfiled))
	}
	_, err = fmt.Fprint(app.Stdout, b.String())
	return err
}

// listTags prints the tags, with how many entries have each.
func listTags(app *App) error {
	store, err := openFilingStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	tags, untagged, err := store.Tags()
	if err != nil {
		return err
	}
	var b strings.Builder
	if len(tags) == 0 {
		b.WriteString("No tags yet. Tag entries with: sesh tag add <tag> <id>…\n")
	} else {
		b.WriteString("Tags:\n")
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		for _, t := range tags {
			if _, err := fmt.Fprintf(tw, "  %s\t%d\n", t.Name, t.Entries); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if untagged > 0 {
		fmt.Fprintf(&b, "%s no tags.\n", hasHave(untagged))
	}
	_, err = fmt.Fprint(app.Stdout, b.String())
	return err
}

// isAre is "1 entry is" or "3 entries are".
func isAre(n int) string {
	if n == 1 {
		return "1 entry is"
	}
	return entryCount(n) + " are"
}

// hasHave is "1 entry has" or "3 entries have".
func hasHave(n int) string {
	if n == 1 {
		return "1 entry has"
	}
	return entryCount(n) + " have"
}

package provider

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/bashhack/sesh/internal/vault"
)

// FilingFlags are --folder and --tag. Storing an entry, they file it;
// listing, searching, or exporting, they narrow the entries to those in the
// folder (or one under it) with every tag.
type FilingFlags struct {
	folder folderFlag
	tags   tagsFlag
}

// Register adds --folder and --tag to fs.
func (f *FilingFlags) Register(fs FlagSet) {
	fs.Var(&f.folder, "folder", folderUsage)
	fs.Var(&f.tags, "tag", tagUsage)
}

// FlagInfo describes --folder and --tag.
func (f *FilingFlags) FlagInfo() []FlagInfo {
	return []FlagInfo{
		{Name: "folder", Type: "string", Description: folderUsage},
		{Name: "tag", Type: "string", Description: tagUsage},
	}
}

const (
	folderUsage = `Folder, such as work/aws: to file an entry in as it's stored, or to list, search, or export only the entries in it and the folders under it ("" for no folder)`
	tagUsage    = "Tag: to add to an entry as it's stored, or to list, search, or export only the entries with it; repeat for more"
)

// Filing is what the flags say, for storing an entry.
func (f *FilingFlags) Filing() vault.Filing {
	return vault.Filing{Folder: f.folder.value, FolderSet: f.folder.given, Tags: f.tags}
}

// Filter is what the flags say, for listing entries.
func (f *FilingFlags) Filter() vault.Filter {
	return vault.Filter{Folder: f.folder.value, FolderSet: f.folder.given, Tags: f.tags}
}

// Filer is a provider whose --folder and --tag file the entries it stores
// and narrow the ones it lists.
type Filer interface {
	// Filing is what --folder and --tag say.
	Filing() vault.Filing
	// UsesFiling reports whether the command, other than --setup or
	// --list, uses --folder and --tag; when it doesn't, where says what
	// they go with.
	UsesFiling() (ok bool, where string)
}

// NoMatchHint says why f found nothing when its folder or a tag isn't on
// any entry in store, with the ones that differ only by case: "there's no
// folder "Work"; did you mean work? Folders and tags are case-sensitive".
// It's "" when they all exist and only together match nothing.
func NoMatchHint(store vault.Store, f *vault.Filter) string {
	all, err := store.List(&vault.Filter{})
	if err != nil {
		return ""
	}
	folders, tags := map[string]bool{}, map[string]bool{}
	for i := range all {
		for p := all[i].Folder; p != ""; p, _ = path.Split(strings.TrimSuffix(p, "/")) {
			folders[strings.TrimSuffix(p, "/")] = true
		}
		for _, t := range all[i].Tags {
			tags[t] = true
		}
	}
	var missing []string
	cased := false
	note := func(what, name string, have map[string]bool) {
		if have[name] {
			return
		}
		var twins []string
		for h := range have {
			if strings.EqualFold(h, name) {
				twins = append(twins, h)
			}
		}
		sort.Strings(twins)
		m := fmt.Sprintf("there's no %s %q", what, name)
		if len(twins) > 0 {
			m += "; did you mean " + strings.Join(twins, " or ") + "?"
			cased = true
		}
		missing = append(missing, m)
	}
	if f.FolderSet && f.Folder != "" {
		note("folder", f.Folder, folders)
	}
	for _, t := range f.Tags {
		note("tag", t, tags)
	}
	if len(missing) == 0 {
		return ""
	}
	hint := strings.Join(missing, "; ")
	if cased {
		if !strings.HasSuffix(hint, "?") {
			hint += "."
		}
		hint += " Folders and tags are case-sensitive"
	}
	return hint
}

// folderFlag is --folder. given tells --folder "" (no folder) from no flag.
type folderFlag struct {
	value string
	given bool
}

func (f *folderFlag) String() string { return f.value }

func (f *folderFlag) Set(v string) error {
	f.value, f.given = v, true
	return nil
}

// tagsFlag is --tag, once per tag.
type tagsFlag []string

func (t *tagsFlag) String() string { return strings.Join(*t, " ") }

func (t *tagsFlag) Set(v string) error {
	*t = append(*t, v)
	return nil
}

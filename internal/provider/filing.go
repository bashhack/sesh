package provider

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"

	"github.com/bashhack/sesh/internal/vault"
)

// FilingFlags are --folder and --tag. Storing an entry, they file it;
// listing, searching, or exporting, they narrow the entries to those in the
// folder (or one under it) with every tag.
type FilingFlags struct {
	folder folderFlag
	tags   tagsFlag
}

// Register adds --folder and --tag to fs. narrows names what they narrow,
// such as "--list".
func (f *FilingFlags) Register(fs FlagSet, narrows string) {
	fs.Var(&f.folder, "folder", folderUsage(narrows))
	fs.Var(&f.tags, "tag", tagUsage(narrows))
}

// FlagInfo describes --folder and --tag, as Register does.
func (f *FilingFlags) FlagInfo(narrows string) []FlagInfo {
	return []FlagInfo{
		{Name: "folder", Type: "string", Description: folderUsage(narrows)},
		{Name: "tag", Type: "string", Description: tagUsage(narrows)},
	}
}

func folderUsage(narrows string) string {
	return `Folder, such as work/aws: to file an entry in as it's stored, or with ` + narrows + `, only the entries in it and the folders under it ("" for no folder)`
}

func tagUsage(narrows string) string {
	return "Tag: to add to an entry as it's stored, or with " + narrows + ", only the entries with it; repeat for more"
}

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
// any entry of f's kind and service in store, naming the ones that differ
// only by case: there's no folder "Work" (did you mean work?). among names
// those entries ("TOTP entries"), "" for the whole vault. The hint is ""
// when the folder and tags all exist and only together match nothing.
func NoMatchHint(store vault.Store, f *vault.Filter, among string) string {
	folders, tags, err := filingNames(store, f)
	if err != nil {
		return ""
	}
	where := ""
	if among != "" {
		where = " among " + among
	}
	var missing []string
	cased := false
	note := func(what, name string, have map[string]bool) {
		if have[name] {
			return
		}
		twins := twinsOf(have, name)
		m := fmt.Sprintf("there's no %s %s%s", what, QuoteName(name), where)
		if len(twins) > 0 {
			m += " (did you mean " + strings.Join(twins, " or ") + "?)"
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
		hint += ". Folders and tags are case-sensitive"
	}
	return hint
}

// filingNames returns the folders (with the folders above them) and tags
// of the entries of f's kind and service.
func filingNames(store vault.Store, f *vault.Filter) (folders, tags map[string]bool, err error) {
	all, err := store.List(&vault.Filter{Kind: f.Kind, Service: f.Service})
	if err != nil {
		return nil, nil, err
	}
	folders, tags = map[string]bool{}, map[string]bool{}
	for i := range all {
		for p := all[i].Folder; p != ""; p, _ = path.Split(strings.TrimSuffix(p, "/")) {
			folders[strings.TrimSuffix(p, "/")] = true
		}
		for _, t := range all[i].Tags {
			tags[t] = true
		}
	}
	return folders, tags, nil
}

// twinsOf returns the names in have that differ from name only by case or
// accent spelling, quoted and sorted.
func twinsOf(have map[string]bool, name string) []string {
	var twins []string
	for h := range have {
		if h != name && foldEqual(h, name) {
			twins = append(twins, QuoteName(h))
		}
	}
	sort.Strings(twins)
	return twins
}

// TwinNote warns that a folder or tag (what) about to be used, which no
// entry has yet, differs only by case from one that some have: "note:
// there's already a folder "work", which differs only by case; folders and
// tags are case-sensitive". It's "" otherwise.
func TwinNote(store vault.Store, what, name string) string {
	folders, tags, err := filingNames(store, &vault.Filter{})
	if err != nil {
		return ""
	}
	have := tags
	if what == "folder" {
		have = folders
	}
	if have[name] {
		return ""
	}
	twins := twinsOf(have, name)
	if len(twins) == 0 {
		return ""
	}
	return fmt.Sprintf("note: there's already a %s %s, which differs only by case; folders and tags are case-sensitive", what, strings.Join(twins, " or "))
}

// foldEqual reports whether a and b differ only by case, or by how an
// accented letter is written ("é" as one character or "e" and an accent).
func foldEqual(a, b string) bool {
	return strings.EqualFold(norm.NFC.String(a), norm.NFC.String(b))
}

// QuoteName quotes a folder or tag for a message, escaping accent marks so
// two spellings that look the same show as different.
func QuoteName(s string) string {
	if strings.ContainsFunc(s, func(r rune) bool { return unicode.In(r, unicode.Mn, unicode.Mc, unicode.Me) }) {
		return fmt.Sprintf("%+q", s)
	}
	return fmt.Sprintf("%q", s)
}

// Scope describes f's folder and tags for a message: in folder "work" with
// tags "a" and "b"; "" when it names neither.
func Scope(f *vault.Filter) string {
	var parts []string
	switch {
	case f.FolderSet && f.Folder == "":
		parts = append(parts, "in no folder")
	case f.FolderSet:
		parts = append(parts, "in folder "+QuoteName(f.Folder))
	}
	if len(f.Tags) > 0 {
		quoted := make([]string, len(f.Tags))
		for i, t := range f.Tags {
			quoted[i] = QuoteName(t)
		}
		tags := "with tag " + quoted[0]
		if len(quoted) > 1 {
			tags = "with tags " + strings.Join(quoted[:len(quoted)-1], ", ") + " and " + quoted[len(quoted)-1]
		}
		parts = append(parts, tags)
	}
	return strings.Join(parts, " ")
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

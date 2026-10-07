package provider

import (
	"strings"

	"github.com/bashhack/sesh/internal/vault"
)

// FilingFlags are --folder and --tag, which file an entry as it's stored.
type FilingFlags struct {
	folder folderFlag
	tags   tagsFlag
}

// Register adds --folder and --tag to fs.
func (f *FilingFlags) Register(fs FlagSet) {
	fs.Var(&f.folder, "folder", "Folder to file the entry in, such as work/aws (\"\" for none)")
	fs.Var(&f.tags, "tag", "Tag to add to the entry; repeat for more")
}

// FlagInfo describes --folder and --tag.
func (f *FilingFlags) FlagInfo() []FlagInfo {
	return []FlagInfo{
		{Name: "folder", Type: "string", Description: "Folder to file the entry in, such as work/aws"},
		{Name: "tag", Type: "string", Description: "Tag to add to the entry; repeat for more"},
	}
}

// Filing is what the flags say.
func (f *FilingFlags) Filing() vault.Filing {
	return vault.Filing{Folder: f.folder.value, FolderSet: f.folder.given, Tags: f.tags}
}

// Filer is a provider whose --folder and --tag file the entries it stores.
type Filer interface {
	// Filing is what --folder and --tag say.
	Filing() vault.Filing
	// Storing reports whether the command, without --setup, stores an
	// entry; when it doesn't, where says what --folder and --tag go with.
	Storing() (ok bool, where string)
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

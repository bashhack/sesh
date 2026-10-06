package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWrites_KeepASymlinkedConfigFile(t *testing.T) {
	for name, tt := range map[string]struct {
		write    func(path string) error
		existing bool
	}{
		"Write on a linked file":        {func(p string) error { return Write(p, "clipboard_timeout = \"45s\"\n") }, true},
		"Write through a dangling link": {func(p string) error { return Write(p, "clipboard_timeout = \"45s\"\n") }, false},
	} {
		t.Run(name, func(t *testing.T) {
			dotfiles := filepath.Join(t.TempDir(), "dotfiles", "sesh")
			if err := os.MkdirAll(dotfiles, 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(dotfiles, "config.toml")
			if tt.existing {
				writeConfig(t, target, "clipboard_timeout = \"10s\"\n")
			}
			link := filepath.Join(t.TempDir(), "sesh", "config.toml")
			if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}

			if err := tt.write(link); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(link)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&os.ModeSymlink == 0 {
				t.Error("the symlink was replaced by a regular file")
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "clipboard_timeout = \"45s\"\n" {
				t.Errorf("linked file = %q", got)
			}
		})
	}
}

func TestWrite_FollowsAChainOfDanglingLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "repo", "config.toml") // doesn't exist yet
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	middle := filepath.Join(dir, "middle.toml")
	if err := os.Symlink(filepath.Join("repo", "config.toml"), middle); err != nil { // relative
		t.Fatal(err)
	}
	link := filepath.Join(dir, "config.toml")
	if err := os.Symlink(middle, link); err != nil {
		t.Fatal(err)
	}

	if err := Write(link, "clipboard_timeout = \"45s\"\n"); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{link, middle} {
		info, err := os.Lstat(l)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			t.Errorf("%s was replaced by a regular file", filepath.Base(l))
		}
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "clipboard_timeout = \"45s\"\n" {
		t.Errorf("end of the chain = %q, %v", got, err)
	}
}

func TestWrite_RefusesALoopOfLinks(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.toml"), filepath.Join(dir, "b.toml")
	if err := os.Symlink(b, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	if err := Write(a, "clipboard_timeout = \"45s\"\n"); err == nil {
		t.Fatal("Write followed a loop of links without failing")
	}
}

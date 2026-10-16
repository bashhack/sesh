package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
)

// fileVault is a vault with a text file entry (kubeconfig, from a file
// named config) and a binary one (cert, piped in), with dir holding the
// files.
func fileVault(t *testing.T) (env *rekeyTestEnv, dir string) {
	t.Helper()
	env = setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "file-password-1234")
	populatePasswordStore(t, env, map[string]string{"password/github/alice": "pw"})
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte("apiVersion: v1\nclusters: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, _ := cliApp("", false)
	if _, said, err := runCLI(app, runAdd, "file", "kubeconfig", "--from", filepath.Join(dir, "config")); err != nil || !strings.Contains(said, "✅ Added file kubeconfig: config, 28 bytes") {
		t.Fatalf("add --from: %q, %v", said, err)
	}
	app, _ = cliApp("\x00\x01binary\xff", false)
	if _, said, err := runCLI(app, runAdd, "file", "cert"); err != nil || !strings.Contains(said, "✅ Added file cert: 9 bytes") {
		t.Fatalf("add piped: %q, %v", said, err)
	}
	return env, dir
}

// A file is kept whole: get gives it back exactly, -o writes it, and a binary one isn't printed at a terminal.
func TestFileEntry_AddAndGet(t *testing.T) {
	_, dir := fileVault(t)
	app, _ := cliApp("", false)
	if out, _, err := runCLI(app, runGet, "kubeconfig"); err != nil || out != "apiVersion: v1\nclusters: []\n" {
		t.Errorf("get: %q, %v", out, err)
	}
	app, _ = cliApp("", false)
	if out, _, err := runCLI(app, runGet, "cert"); err != nil || out != "\x00\x01binary\xff" {
		t.Errorf("get, piped: %q, %v", out, err)
	}
	old := uiStdoutIsTerminal
	t.Cleanup(func() { uiStdoutIsTerminal = old })
	uiStdoutIsTerminal = func(io.Writer) bool { return true }
	app, _ = cliApp("", false)
	if out, _, err := runCLI(app, runGet, "cert"); err == nil || out != "" || !strings.Contains(err.Error(), "binary file (9 bytes), which isn't printed at a terminal: add -o FILE") {
		t.Errorf("binary at a terminal: %q, %v", out, err)
	}
	app, _ = cliApp("", false)
	to := filepath.Join(dir, "out.bin")
	if _, said, err := runCLI(app, runGet, "cert", "-o", to); err != nil || !strings.Contains(said, "readable only by you") {
		t.Errorf("-o: %q, %v", said, err)
	}
	if b, err := os.ReadFile(to); err != nil || string(b) != "\x00\x01binary\xff" {
		t.Errorf("-o wrote %q, %v", b, err)
	}
	if info, err := os.Stat(to); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("-o's mode: %v, %v", info.Mode(), err)
	}
	app, _ = cliApp("", false)
	out, _, err := runCLI(app, runGet, "cert", "--json")
	var got struct{ Value, Encoding, Part string }
	if err != nil || json.Unmarshal([]byte(out), &got) != nil || got.Encoding != "base64" || got.Value != base64.StdEncoding.EncodeToString([]byte("\x00\x01binary\xff")) {
		t.Errorf("--json: %q, %v", out, err)
	}
	app, _ = cliApp("", false)
	if _, _, err := runCLI(app, runGet, "cert", "--json", "-o", to); err == nil || !strings.Contains(err.Error(), "choose one") {
		t.Errorf("--json and -o: %v", err)
	}
	app, _ = cliApp("", false)
	if _, _, err := runCLI(app, runGet, "cert", "-o", dir); err == nil || !strings.Contains(err.Error(), "is a folder") {
		t.Errorf("-o a folder: %v", err)
	}
	// A text file is copied; a binary one isn't.
	app, copied := cliApp("", false)
	if _, _, err := runCLI(app, runCopy, "kubeconfig"); err != nil || len(*copied) != 1 || (*copied)[0] != "apiVersion: v1\nclusters: []\n" {
		t.Errorf("copy: %q, %v", *copied, err)
	}
	app, copied = cliApp("", false)
	if _, _, err := runCLI(app, runCopy, "cert"); err == nil || len(*copied) != 0 || !strings.Contains(err.Error(), "binary file, which the clipboard can't hold") {
		t.Errorf("copy binary: %q, %v", *copied, err)
	} // Replaced from a pipe, a file keeps its name.
	app, _ = cliApp("apiVersion: v3\n", false)
	if _, _, err := runCLI(app, runAdd, "file", "kubeconfig", "--force"); err != nil {
		t.Fatal(err)
	}
	if out, err := runShowOut(t, "file/kubeconfig"); err != nil || !strings.Contains(out, "File     config, 15 bytes") {
		t.Errorf("replaced from a pipe: %q, %v", out, err)
	}
}

// A file that can't be kept is refused, saying why; one piped in before a vault is made.
func TestFileEntry_AddRefused(t *testing.T) {
	_, dir := fileVault(t)
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, 1<<20+1), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for args, wantSub := range map[string]string{
		"file x --from " + big:           "is 1,048,577 bytes; a file entry holds up to 1 MiB (1,048,576 bytes)",
		"file x --from " + empty:         "is empty",
		"file x --from " + dir:           "is a folder",
		"file x --from " + dir + "/none": "no such file",
		"password x --from " + empty:     "--from reads a file entry's file",
		"file x --generate":              "--generate makes a password; a file comes from wherever it was issued",
	} {
		app, _ := cliApp("", false)
		if _, _, err := runCLI(app, runAdd, strings.Fields(args)...); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%s: %v, want %q", args, err, wantSub)
		}
	}
	// Given no name, it's named after its file.
	if err := os.WriteFile(filepath.Join(dir, "server.key"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, _ := cliApp("", false)
	if _, said, err := runCLI(app, runAdd, "file", "--from", filepath.Join(dir, "server.key")); err != nil || !strings.Contains(said, "Added file server.key: server.key, 3 bytes") {
		t.Errorf("no name: %q, %v", said, err)
	}
	// A pipe is read, and checked, before a vault is made.
	fresh := setupRekeyEnv(t)
	useConfigFile(t, "")
	for in, wantSub := range map[string]string{"": "the file piped in is empty", strings.Repeat("x", 1<<20+1): "is over 1 MiB"} {
		app, _ = cliApp(in, false)
		if _, _, err := runCLI(app, runAdd, "file", "x"); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("piped %d bytes: %v, want %q", len(in), err, wantSub)
		}
	}
	if _, err := os.Stat(fresh.dbPath); !os.IsNotExist(err) {
		t.Errorf("a vault was made: %v", err)
	}
	app, _ = cliApp("", true)
	if _, _, err := runCLI(app, runAdd, "file", "x"); err == nil || !strings.Contains(err.Error(), "give the file: sesh add file <name> --from FILE, or pipe it in") {
		t.Errorf("no file at a terminal: %v", err)
	}
}

// show names the file and its size, hiding its content unless revealed; a binary one isn't shown even then.
func TestFileEntry_Show(t *testing.T) {
	env, _ := fileVault(t)
	before := auditEvents(t, env.dbPath)
	out, err := runShowOut(t, "file/kubeconfig")
	if err != nil || out != "file/kubeconfig\n  File     config, 28 bytes\n  Content  ••••••••   (get, or --reveal)\n" {
		t.Errorf("show: %q, %v", out, err)
	}
	if after := auditEvents(t, env.dbPath); after["access"] != before["access"] {
		t.Errorf("showing it hidden read it")
	}
	if bin, err := runShowOut(t, "file/cert", "--reveal"); err != nil || !strings.Contains(bin, "Content  (binary: sesh get file/cert -o FILE writes it)") {
		t.Errorf("reveal binary: %q, %v", bin, err)
	}
	out, err = runShowOut(t, "file/kubeconfig", "--json", "--reveal")
	if err != nil {
		t.Fatalf("--json: %q, %v", out, err)
	}
	var shown struct {
		Secret   string `json:"secret"`
		Encoding string `json:"encoding"`
		FileName string `json:"file_name"`
		Size     int64  `json:"size"`
	}
	if err := json.Unmarshal([]byte(out), &shown); err != nil || shown.Encoding != "base64" || shown.FileName != "config" || shown.Size != 28 || shown.Secret != base64.StdEncoding.EncodeToString([]byte("apiVersion: v1\nclusters: []\n")) {
		t.Errorf("--json: %+v, %v", shown, err)
	}
	if out := mustRun(t, runList, "files"); !strings.Contains(out, "file/kubeconfig") || !strings.Contains(out, "file/cert") || strings.Contains(out, "github") {
		t.Errorf("list files:\n%s", out)
	}
	if out := mustRun(t, runList, "files", "--json"); !strings.Contains(out, `"file_name": "config"`) || !strings.Contains(out, `"size": 28`) {
		t.Errorf("list files --json:\n%s", out)
	}
}

// edit --from gives a file entry a new file, keeping the old one in its history; other kinds take no file, nor a file a typed secret.
func TestFileEntry_Edit(t *testing.T) {
	_, dir := fileVault(t)
	next := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(next, []byte("apiVersion: v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, _, err := runEditOut(t, "", false, "file/kubeconfig", "--from", next); err != nil || !strings.Contains(out, "secret changed and file name changed") {
		t.Errorf("edit --from: %q, %v", out, err)
	}
	if out, err := runShowOut(t, "file/kubeconfig"); err != nil || !strings.Contains(out, "config.yml, 15 bytes") {
		t.Errorf("after: %q, %v", out, err)
	}
	if out := mustRun(t, runHistory, "file/kubeconfig", "--show", "2"); out != "apiVersion: v1\nclusters: []\n" {
		t.Errorf("history --show 2: %q", out)
	}
	// Brought back, a version has its own file's name again.
	mustRun(t, runHistory, "file/kubeconfig", "--restore", "2")
	if out, err := runShowOut(t, "file/kubeconfig"); err != nil || !strings.Contains(out, "File     config, 28 bytes") {
		t.Errorf("after restoring version 2: %q, %v", out, err)
	}
	mustRun(t, runHistory, "file/kubeconfig", "--restore", "2")
	if out, err := runShowOut(t, "file/kubeconfig"); err != nil || !strings.Contains(out, "File     config.yml, 15 bytes") {
		t.Errorf("after restoring version 2 again: %q, %v", out, err)
	}
	if _, said, err := runEditOut(t, "", false, "file/kubeconfig", "--from", next); err != nil || !strings.Contains(said, "Nothing changed: the entry already has that file") {
		t.Errorf("the same file again: %q, %v", said, err)
	}
	for args, wantSub := range map[string]string{
		"file/kubeconfig --secret":             "--from FILE gives it a new one",
		"file/kubeconfig --generate":           "--from FILE gives it a new one",
		"password/github/alice --from " + next: "--from gives a file entry its file, and password/github/alice is a password",
		"file/kubeconfig --type password":      "a file entry stays one",
		"password/github/alice --type file":    "a file entry stays one",
	} {
		if _, _, err := runEditOut(t, "x\n", false, strings.Fields(args)...); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%s: %v, want %q", args, err, wantSub)
		}
	}
}

// A JSON export holds a file in base64, which importing reads back; CSV leaves files out, saying so.
func TestFileEntry_ExportImport(t *testing.T) {
	_, dir := fileVault(t)
	to := filepath.Join(dir, "all.json")
	app, _ := cliApp("", false)
	if _, said, err := runCLI(app, runExport, "--format", "json", "--file", to); err != nil || !strings.Contains(said, "Exported 3 entries") {
		t.Fatalf("export json: %q, %v", said, err)
	}
	b, err := os.ReadFile(to)
	if err != nil || !strings.Contains(string(b), `"encoding": "base64"`) || !strings.Contains(string(b), `"file_name": "config"`) {
		t.Errorf("the JSON export:\n%s", b)
	}
	app, _ = cliApp("", false)
	csvTo := filepath.Join(dir, "all.csv")
	if _, said, err := runCLI(app, runExport, "--format", "csv", "--file", csvTo); err != nil || !strings.Contains(said, "Exported 1 entry") || !strings.Contains(said, "2 file entries left out") {
		t.Errorf("export csv: %q, %v", said, err)
	}
	if b, err := os.ReadFile(csvTo); err != nil || strings.Contains(string(b), "kubeconfig") {
		t.Errorf("the CSV export:\n%s", b)
	}
	// Files alone in CSV would be an empty export, so it's refused, and the file there kept.
	app, _ = cliApp("", false)
	if _, _, err := runCLI(app, runExport, "files", "--format", "csv", "--force", "--file", csvTo); err == nil || !strings.Contains(err.Error(), "leaves files out") {
		t.Errorf("export files as csv: %v", err)
	}
	if b, err := os.ReadFile(csvTo); err != nil || !strings.Contains(string(b), "\n") || strings.Count(string(b), "\n") < 2 {
		t.Errorf("the CSV export there was replaced:\n%s", b)
	}
	// Into a fresh vault, the files come back whole.
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "file-password-1234")
	populatePasswordStore(t, env, map[string]string{"password/other": "x"})
	app, _ = cliApp("", false)
	if _, said, err := runCLI(app, runImport, "--from", "sesh", "--yes", to); err != nil {
		t.Fatalf("import: %q, %v", said, err)
	}
	app, _ = cliApp("", false)
	if out, _, err := runCLI(app, runGet, "cert"); err != nil || out != "\x00\x01binary\xff" {
		t.Errorf("imported cert: %q, %v", out, err)
	}
	store := openDoctorVault(t, env)
	defer store.Close() //nolint:errcheck // test cleanup
	if e, err := store.Lookup(vault.Key{Kind: vault.KindFile, Service: "kubeconfig"}); err != nil || e.Settings.FileName != "config" || e.Size != 28 {
		t.Errorf("imported kubeconfig: %+v, %v", e, err)
	}
}

// sesh run gives a command a file reference as the path of a private copy, gone once it ends.
func TestFileEntry_Run(t *testing.T) {
	fileVault(t)
	app, _ := cliApp("", false)
	out, _, err := runCLI(app, runRun, "--env", "KUBECONFIG=sesh://file/kubeconfig", "--", "sh", "-c", `echo "$KUBECONFIG"; cat "$KUBECONFIG"; ls -ld "$(dirname "$KUBECONFIG")" | cut -c1-10; ls -l "$KUBECONFIG" | cut -c1-10`)
	if err != nil {
		t.Fatalf("run: %q, %v", out, err)
	}
	lines := strings.SplitN(out, "\n", 2)
	path := lines[0]
	if filepath.Base(path) != "config" || !strings.Contains(lines[1], "apiVersion: v1\nclusters: []\n") || !strings.Contains(lines[1], "drwx------\n-rw-------") {
		t.Errorf("the command saw:\n%s", out)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Errorf("the folder is still there: %v", err)
	}
	// inject puts the content in.
	app, _ = cliApp("kube: {{ sesh://file/kubeconfig }}", false)
	if out, _, err := runCLI(app, runInject); err != nil || out != "kube: apiVersion: v1\nclusters: []\n" {
		t.Errorf("inject: %q, %v", out, err)
	}
}

// The app reads and writes files at paths typed from ~/ or in full, keeping a file that's there already.
func TestUIFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("kube"), 0o600); err != nil {
		t.Fatal(err)
	}
	if content, name, err := uiReadFile("~/config"); err != nil || string(content) != "kube" || name != "config" {
		t.Errorf("read: %q, %q, %v", content, name, err)
	}
	if _, _, err := uiReadFile("config"); err == nil || !strings.Contains(err.Error(), "isn't a full path") {
		t.Errorf("a relative path: %v", err)
	}
	if where, err := uiSaveFile("~/out", []byte("kube")); err != nil || where != "~/out" {
		t.Errorf("save: %q, %v", where, err)
	}
	if info, err := os.Stat(filepath.Join(home, "out")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("saved: %v, %v", info, err)
	}
	if _, err := uiSaveFile("~/config", []byte("other")); err == nil || !strings.Contains(err.Error(), "there's already a file at ~/config") {
		t.Errorf("onto a file: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(home, "config")); string(b) != "kube" { //nolint:errcheck // checked by content
		t.Errorf("the file there was changed: %q", b)
	}
}

// A sesh export's file name that isn't a name alone, or has control characters, is skipped on import, saying why.
func TestFileEntry_ImportChecksNames(t *testing.T) {
	fileVault(t)
	dir := t.TempDir()
	export := `[
  {"service": "evil", "type": "file", "secret": "aGk=", "encoding": "base64", "settings": {"file_name": ".ssh/authorized_keys"}},
  {"service": "loud", "type": "file", "secret": "aGk=", "encoding": "base64", "settings": {"file_name": "\u001b[31mRED"}},
  {"service": "fine", "type": "file", "secret": "aGk=", "encoding": "base64", "settings": {"file_name": "fine.txt"}}
]`
	path := filepath.Join(dir, "crafted.json")
	if err := os.WriteFile(path, []byte(export), 0o600); err != nil {
		t.Fatal(err)
	}
	app, _ := cliApp("", false)
	out, said, err := runCLI(app, runImport, "--from", "sesh", "--yes", path)
	if err != nil || !strings.Contains(out+said, "isn't a file's name alone") || !strings.Contains(out+said, "has a control character") {
		t.Errorf("import: %q, %q, %v", out, said, err)
	}
	app, _ = cliApp("", false)
	if got, _, err := runCLI(app, runGet, "fine"); err != nil || got != "hi" {
		t.Errorf("the fine one: %q, %v", got, err)
	}
	for _, name := range []string{"evil", "loud"} {
		app, _ = cliApp("", false)
		if _, _, err := runCLI(app, runGet, name); err == nil {
			t.Errorf("%s was imported", name)
		}
	}
}

// recordingReader gives n bytes of x, a little at a time, keeping each
// buffer it was handed.
type recordingReader struct {
	seen [][]byte
	n    int
}

func (r *recordingReader) Read(p []byte) (int, error) {
	if r.n == 0 {
		return 0, io.EOF
	}
	r.seen = append(r.seen, p[:cap(p)])
	k := min(len(p), r.n, 1000)
	for i := range k {
		p[i] = 'x'
	}
	r.n -= k
	return k, nil
}

// Reading a file of unknown size leaves no copy of it in a buffer it outgrew.
func TestReadAtMostZeroes(t *testing.T) {
	r := &recordingReader{n: 20000}
	got, err := readAtMost(r, "a pipe", 0)
	if err != nil || len(got) != 20000 {
		t.Fatalf("read %d, %v", len(got), err)
	}
	final := &got[:cap(got)][cap(got)-1]
	outgrown := 0
	for _, b := range r.seen {
		if &b[len(b)-1] == final {
			continue
		}
		outgrown++
		for _, c := range b {
			if c != 0 {
				t.Fatalf("a buffer outgrown still holds %q", c)
			}
		}
	}
	if outgrown == 0 {
		t.Fatal("no buffer was outgrown: the test proves nothing")
	}
}

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
	// A text file is copied; a binary one isn't.
	app, copied := cliApp("", false)
	if _, _, err := runCLI(app, runCopy, "kubeconfig"); err != nil || len(*copied) != 1 || (*copied)[0] != "apiVersion: v1\nclusters: []\n" {
		t.Errorf("copy: %q, %v", *copied, err)
	}
	app, copied = cliApp("", false)
	if _, _, err := runCLI(app, runCopy, "cert"); err == nil || len(*copied) != 0 || !strings.Contains(err.Error(), "binary file, which the clipboard can't hold") {
		t.Errorf("copy binary: %q, %v", *copied, err)
	}
}

// A file that can't be kept is refused before anything is unlocked, saying why.
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
		"file x --from " + big:           "a file entry holds up to 1.0 MB",
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

package aws

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The helpers parse in each shell sesh aws's shell may be.
func TestSubshellFunctions_Parse(t *testing.T) {
	for _, sh := range []string{"sh", "bash", "zsh"} {
		path, err := exec.LookPath(sh)
		if err != nil {
			continue
		}
		cmd := exec.Command(path, "-n") //nolint:gosec // a shell found on PATH, for the test
		cmd.Stdin = strings.NewReader(NewCustomizer().Functions())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s -n: %v\n%s", sh, err, out)
		}
	}
	if got := NewCustomizer().PromptPrefix(); got != "(sesh:aws) " {
		t.Errorf("PromptPrefix() = %q", got)
	}
}

// verify_aws says who the credentials sign in as, or what AWS said.
func TestVerifyAWS(t *testing.T) {
	for name, tc := range map[string]struct {
		script, want string
		ok           bool
	}{
		"accepted": {`echo arn:aws:iam::123456789012:user/alice`, "✅ The credentials work: signed in as arn:aws:iam::123456789012:user/alice", true},
		"refused":  {`echo "An error occurred (ExpiredToken)" >&2; exit 254`, "❌ AWS didn't accept the credentials: An error occurred (ExpiredToken)", false},
	} {
		t.Run(name, func(t *testing.T) {
			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "aws"), []byte("#!/bin/sh\n"+tc.script+"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/sh", "-c", SubshellFunctions+"\nverify_aws")
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "SESH_SERVICE=aws"}
			out, err := cmd.Output()
			if got := strings.TrimSpace(string(out)); !strings.Contains(got, tc.want) || (err == nil) != tc.ok {
				t.Errorf("verify_aws: %q, %v; want %q, ok %v", got, err, tc.want, tc.ok)
			}
		})
	}
}

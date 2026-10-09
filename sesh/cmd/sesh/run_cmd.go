package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/bashhack/sesh/internal/mask"
	"github.com/bashhack/sesh/internal/secretref"
	"github.com/bashhack/sesh/internal/secure"
)

// exitStatus is a command's exit status, for sesh to exit with; fatal
// exits with it and prints nothing.
type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// repeatedFlag is a flag given once per value.
type repeatedFlag []string

func (r *repeatedFlag) String() string { return strings.Join(*r, " ") }

func (r *repeatedFlag) Set(v string) error {
	*r = append(*r, v)
	return nil
}

// runFlags are sesh run's flags.
type runFlags struct {
	env, envFiles repeatedFlag
	noMasking     bool
}

func addRunFlags(fs *flag.FlagSet) *runFlags {
	f := &runFlags{}
	fs.Var(&f.env, "env", "Set NAME=value in the command's environment; value may be a sesh:// reference (repeat for more)")
	fs.Var(&f.envFiles, "env-file", "Read NAME=value lines from a file; values may be sesh:// references (repeat for more)")
	fs.BoolVar(&f.noMasking, "no-masking", false, "Give the command the terminal, without hiding secrets in its output")
	return f
}

const runUsage = `Usage: sesh run [--env NAME=<ref>]... [--env-file <file>]... [--no-masking] -- <command> [args...]
  Run a command with secrets from the vault in its environment. A reference
  is sesh://<id>[#field], with the entry ID as --list shows it.
  Secrets the command prints are shown as <concealed by sesh>, unless
  --no-masking gives it the terminal directly.

  sesh run --env OPENAI_API_KEY=sesh://api_key/openai -- python app.py
  sesh run --env-file .env -- npm start`

// runRun is `sesh run`: every reference is resolved first, with one
// unlock; then the command runs with them in its environment, and sesh
// exits as it does.
func runRun(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, runUsage)
		return err
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	f := addRunFlags(fs)
	fs.Usage = func() { fmt.Fprintln(app.Stderr, runUsage) } //nolint:errcheck // usage text
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	command := fs.Args()
	if len(command) == 0 {
		return errors.New("name the command to run after --: sesh run [flags] -- <command> [args...]")
	}
	vars, err := runVars(f)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(vars, func(v secretref.EnvVar) bool { return v.Ref != nil }) {
		return errors.New("nothing from the vault to give the command: add --env NAME=sesh://<id>, or --env-file with references")
	}
	path, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("can't run %s: %w", command[0], err)
	}

	values, err := resolveRefs(refsOf(vars), "run")
	if err != nil {
		return err
	}
	defer zeroValues(values)
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return name == "SESH_MASTER_PASSWORD" || slices.ContainsFunc(vars, func(v secretref.EnvVar) bool { return v.Name == name })
	})
	var secrets [][]byte
	for _, v := range vars {
		if v.Ref == nil {
			env = append(env, v.Name+"="+v.Value)
			continue
		}
		val := values[v.Ref.String()]
		env = append(env, v.Name+"="+string(val.Value))
		if val.Secret {
			secrets = append(secrets, val.Value)
		}
	}

	cmd := exec.Command(path, command[1:]...) //nolint:gosec // the command the user asked to run
	cmd.Args[0] = command[0]
	cmd.Env = env
	cmd.Stdin = app.Stdin
	var outMask, errMask *mask.Writer
	if f.noMasking {
		cmd.Stdout, cmd.Stderr = app.Stdout, app.Stderr
	} else {
		outMask, errMask = mask.NewWriter(app.Stdout, secrets), mask.NewWriter(app.Stderr, secrets)
		cmd.Stdout, cmd.Stderr = outMask, errMask
	}
	return runChild(cmd, outMask, errMask)
}

// outputDrain is how long sesh waits, once the command has exited, for
// the rest of its output: a process it left running in the background may
// hold its output open long after.
const outputDrain = time.Second

// runChild runs cmd to its end and returns its exit status as an
// exitStatus (none for 0). Ctrl-C and Ctrl-\ reach the command from the
// terminal, so sesh only waits through them; a request to stop or a
// closed terminal is passed on to it. Output still coming outputDrain
// after the command exits, from a process it left behind, isn't shown.
func runChild(cmd *exec.Cmd, masks ...*mask.Writer) error {
	cmd.WaitDelay = outputDrain
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("can't run %s: %w", cmd.Args[0], err)
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigs:
				if sig == syscall.SIGTERM || sig == syscall.SIGHUP {
					_ = cmd.Process.Signal(sig) //nolint:errcheck // it may have ended
				}
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	if errors.Is(err, exec.ErrWaitDelay) {
		err = nil // the command itself succeeded
	}
	for _, m := range masks {
		if m != nil {
			if cerr := m.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}
	}
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return exitStatus(128 + int(ws.Signal()))
		}
		return exitStatus(exit.ExitCode())
	}
	return err
}

// runVars are the variables the env files, then the --env flags, set; a
// later one replaces an earlier one of the same name.
func runVars(f *runFlags) ([]secretref.EnvVar, error) {
	var vars []secretref.EnvVar
	set := func(v secretref.EnvVar) {
		vars = slices.DeleteFunc(vars, func(o secretref.EnvVar) bool { return o.Name == v.Name })
		vars = append(vars, v)
	}
	for _, name := range f.envFiles {
		file, err := os.Open(name) //nolint:gosec // the file the user named
		if err != nil {
			return nil, err
		}
		fileVars, err := secretref.ParseEnvFile(file, name)
		_ = file.Close() //nolint:errcheck // read only
		if err != nil {
			return nil, err
		}
		for _, v := range fileVars {
			set(v)
		}
	}
	for _, s := range f.env {
		v, err := secretref.ParseEnvFlag(s)
		if err != nil {
			return nil, err
		}
		set(v)
	}
	return vars, nil
}

func refsOf(vars []secretref.EnvVar) []secretref.Ref {
	var refs []secretref.Ref
	for _, v := range vars {
		if v.Ref != nil {
			refs = append(refs, *v.Ref)
		}
	}
	return refs
}

// resolveRefs opens the vault once and resolves each reference, by its
// text; reading says what for, for the audit log. The vault is closed
// again before anything runs.
func resolveRefs(refs []secretref.Ref, reading string) (map[string]secretref.Value, error) {
	store, err := openFilingStore()
	if err != nil {
		return nil, err
	}
	defer closeAuditStore(store)
	values := map[string]secretref.Value{}
	for _, r := range refs {
		if _, ok := values[r.String()]; ok {
			continue
		}
		v, err := secretref.Resolve(store, r, reading)
		if err != nil {
			zeroValues(values)
			return nil, err
		}
		values[r.String()] = v
	}
	return values, nil
}

func zeroValues(values map[string]secretref.Value) {
	for k, v := range values {
		v.Zero()
		delete(values, k)
	}
}

const injectUsage = `Usage: sesh inject [-i <template>] [-o <file>]
  Fill a template's {{ sesh://<id>[#field] }} references with values from the
  vault. It reads the template from -i or stdin, and writes to -o, created
  readable only by you, or stdout.

  sesh inject -i config.yml.tpl -o config.yml`

func addInjectFlags(fs *flag.FlagSet) (in, out *string) {
	return fs.String("i", "", "The template (default: stdin)"), fs.String("o", "", "The file to write, readable only by you (default: stdout)")
}

// runInject is `sesh inject`: every reference in the template is resolved
// before anything is written, and the file is written whole, with 0600
// permissions, then renamed into place.
func runInject(app *App, args []string) error {
	if len(args) > 0 && isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, injectUsage)
		return err
	}
	fs := flag.NewFlagSet("inject", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	in, out := addInjectFlags(fs)
	fs.Usage = func() { fmt.Fprintln(app.Stderr, injectUsage) } //nolint:errcheck // usage text
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("sesh inject takes -i and -o, not %q", strings.Join(fs.Args(), " "))
	}
	name, r := "the template", app.Stdin
	if *in != "" {
		file, err := os.Open(*in)
		if err != nil {
			return err
		}
		defer file.Close() //nolint:errcheck // read only
		name, r = *in, file
	}
	b, err := io.ReadAll(io.LimitReader(r, 16<<20))
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	tpl := string(b)
	refs, err := secretref.TemplateRefs(tpl, name)
	if err != nil {
		return err
	}
	if len(refs) == 0 {
		return fmt.Errorf("%s has no {{ sesh://... }} references to fill", name)
	}
	values, err := resolveRefs(refs, "inject")
	if err != nil {
		return err
	}
	defer zeroValues(values)
	byRef := make(map[string][]byte, len(values))
	for k, v := range values {
		byRef[k] = v.Value
	}
	filled := secretref.Fill(tpl, byRef)
	defer secure.SecureZeroBytes(filled)
	if *out == "" {
		_, err := app.Stdout.Write(filled)
		return err
	}
	if err := writePrivate(*out, filled); err != nil {
		return err
	}
	_, err = fmt.Fprintf(app.Stderr, "✅ Wrote %s, readable only by you (%d %s filled)\n", *out, len(refs), plural(len(refs), "reference", "references"))
	return err
}

// writePrivate writes b to path, readable only by its owner: whole, to a
// new file beside it, then renamed into place, so a reader never sees
// part of it. A file already there is replaced.
func writePrivate(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".sesh-*")
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			_ = os.Remove(tmp.Name()) //nolint:errcheck // best effort
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close() //nolint:errcheck // already failing
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close() //nolint:errcheck // already failing
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close() //nolint:errcheck // already failing
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	done = true
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

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
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

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
	if f.noMasking {
		cmd.Stdout, cmd.Stderr = app.Stdout, app.Stderr
		return runChild(cmd, nil)
	}
	outMask, errMask := mask.NewWriter(app.Stdout, secrets), mask.NewWriter(app.Stderr, secrets)
	return runChild(cmd, []*mask.Writer{outMask, errMask})
}

// outputIdle is how long sesh waits in all, once the command has exited,
// for more of its output: a process it left running in the background may
// hold its output open long after.
const outputIdle = time.Second

// runChild runs cmd to its end and returns its exit status as an
// exitStatus (none for 0). With masks, the command's stdout and stderr go
// through them, by pipes sesh reads until they end, or, once the command
// has exited, until sesh has waited outputIdle in all for more (see
// copyQuietly).
//
// Signals: Ctrl-C and Ctrl-\ at the terminal reach the command directly,
// so sesh only waits through them; sent to sesh alone, from elsewhere, they
// and a request to stop or a closed terminal are passed on. A command
// killed by SIGINT, SIGTERM, SIGHUP or SIGKILL makes sesh end the same way
// (killedBy), so a shell loop running sesh run stops at Ctrl-C as it would
// for the command; other signals are a status of 128 plus the signal.
func runChild(cmd *exec.Cmd, masks []*mask.Writer) error {
	// exitedAt is when the command exited, in Unix nanoseconds; 0 before.
	var exitedAt atomic.Int64
	var readEnds, writeEnds []*os.File
	var copies []chan struct{}
	defer func() {
		for _, f := range append(readEnds, writeEnds...) {
			_ = f.Close() //nolint:errcheck // a write end is closed after Start too
		}
	}()
	for i, m := range masks {
		r, w, err := os.Pipe()
		if err != nil {
			return err
		}
		if i == 0 {
			cmd.Stdout = w
		} else {
			cmd.Stderr = w
		}
		readEnds, writeEnds = append(readEnds, r), append(writeEnds, w)
		done := make(chan struct{})
		copies = append(copies, done)
		go copyQuietly(r, m, &exitedAt, done)
	}

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		for _, m := range masks {
			_ = m.Close() //nolint:errcheck // zeroes its copies of the secrets
		}
		return fmt.Errorf("can't run %s: %w", cmd.Args[0], err)
	}
	// sesh keeps no write end, so the pipes end when the command, and
	// whatever it left running, let go of them.
	for _, w := range writeEnds {
		_ = w.Close() //nolint:errcheck // the command has its own
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigs:
				if sig == syscall.SIGTERM || sig == syscall.SIGHUP || !fromTerminal() {
					_ = cmd.Process.Signal(sig) //nolint:errcheck // it may have ended
				}
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	now := time.Now()
	exitedAt.Store(now.UnixNano())
	// A read already waiting gets the same cut-off as the next ones.
	for _, r := range readEnds {
		_ = r.SetReadDeadline(now.Add(outputIdle)) //nolint:errcheck // a pipe takes one
	}
	for _, c := range copies {
		<-c
	}
	for _, m := range masks {
		if cerr := m.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			switch sig := ws.Signal(); sig {
			case syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGKILL:
				return killedBy(sig)
			default:
				// Go turns ending by most other signals, such as Ctrl-\ or a
				// crash, into a dump of its own, so these are a status.
				return exitStatus(128 + int(sig))
			}
		}
		return exitStatus(exit.ExitCode())
	}
	return err
}

// copyQuietly copies r to m until r ends, or, once the command has exited
// (exitedAt), until sesh has waited outputIdle in all for more: time spent
// passing output on to a slow reader doesn't count, so all of it arrives,
// while a process left behind, quiet or not, can't hold sesh open.
func copyQuietly(r *os.File, m *mask.Writer, exitedAt *atomic.Int64, done chan struct{}) {
	defer close(done)
	buf := make([]byte, 32<<10)
	defer secure.SecureZeroBytes(buf)
	var waited time.Duration
	for {
		start := time.Now()
		if exitedAt.Load() != 0 {
			left := outputIdle - waited
			if left <= 0 {
				return
			}
			_ = r.SetReadDeadline(start.Add(left)) //nolint:errcheck // a pipe takes one
		}
		n, err := r.Read(buf)
		if at := exitedAt.Load(); at != 0 {
			waited += time.Since(maxTime(start, time.Unix(0, at)))
		}
		if n > 0 {
			if _, werr := m.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// fromTerminal reports whether a Ctrl-C or Ctrl-\ sesh received came from
// its terminal, which sends it to the command too: sesh is in the
// terminal's foreground process group. Tests replace it.
var fromTerminal = func() bool {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return false
	}
	defer tty.Close() //nolint:errcheck // read only
	pgrp, err := unix.IoctlGetInt(int(tty.Fd()), unix.TIOCGPGRP)
	return err == nil && pgrp == syscall.Getpgrp()
}

// killedBy is the error for a command killed by sig (SIGINT, SIGTERM,
// SIGHUP, or SIGKILL): fatal ends sesh by the same signal, so whatever ran
// sesh sees it killed, not exited.
type killedBy syscall.Signal

func (k killedBy) Error() string { return "killed by " + syscall.Signal(k).String() }

// endBy ends sesh by sig, as the command was ended, or with 128+sig if it
// survives it.
func endBy(app *App, sig syscall.Signal) {
	signal.Reset(sig)
	_ = syscall.Kill(syscall.Getpid(), sig) //nolint:errcheck // falls back to exiting
	time.Sleep(100 * time.Millisecond)
	app.Exit(128 + int(sig))
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

// maxTemplate is the largest template sesh inject fills.
const maxTemplate = 16 << 20

// sameFile reports whether paths a and b name one file, so writing b
// would replace a.
func sameFile(a, b string) bool {
	ia, err := os.Stat(a)
	if err != nil {
		return false
	}
	ib, err := os.Stat(b)
	return err == nil && os.SameFile(ia, ib)
}

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
	if *in == "" && app.StdinIsTerminal != nil && app.StdinIsTerminal() {
		return errors.New("give the template with -i, or pipe it in: sesh inject -i <template> [-o <file>]")
	}
	if *in != "" && *out != "" && sameFile(*in, *out) {
		return fmt.Errorf("%s is the template itself: writing the filled file there would replace the template with secrets", *out)
	}
	if *out != "" {
		if info, err := os.Stat(*out); err == nil && info.IsDir() {
			return fmt.Errorf("%s is a folder: give -o a file name", *out)
		}
	}
	if *in != "" {
		file, err := os.Open(*in)
		if err != nil {
			return err
		}
		defer file.Close() //nolint:errcheck // read only
		name, r = *in, file
	}
	b, err := io.ReadAll(io.LimitReader(r, maxTemplate+1))
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	if len(b) > maxTemplate {
		return fmt.Errorf("%s is over 16 MiB, the most sesh inject fills", name)
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
	filled, err := secretref.Fill(tpl, byRef)
	if err != nil {
		return err
	}
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
// part of it. A file already there is replaced; a symlink there is
// replaced by the file, not followed.
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

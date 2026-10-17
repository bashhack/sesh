package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/bashhack/sesh/internal/clipboard"
	"github.com/bashhack/sesh/internal/kdf"
	"github.com/bashhack/sesh/internal/provider"
)

// validEnvVarName matches POSIX-compliant environment variable names.
var validEnvVarName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// ExecLookPathFunc is a function type for looking up executables in PATH
type ExecLookPathFunc func(file string) (string, error)

// ExitFunc is a function type for exiting the program
type ExitFunc func(code int)

// ClipboardCopyFunc is a function type for copying text to clipboard
type ClipboardCopyFunc func(text string) error

// TimeNowFunc is a function type for getting the current time
type TimeNowFunc func() time.Time

// App represents the main application
type App struct {
	ExecLookPath  ExecLookPathFunc
	Exit          ExitFunc
	ClipboardCopy ClipboardCopyFunc
	// ClipboardCheck reports why nothing can be copied here, if so; nil
	// skips the check.
	ClipboardCheck func() error
	// ClipboardCopyFor copies as ClipboardCopy does, clearing it no sooner
	// than atLeast; nil is ClipboardCopy.
	ClipboardCopyFor func(text string, atLeast time.Duration) error
	// ClipboardRead returns what the clipboard holds; nil can't tell.
	ClipboardRead func() (string, error)
	TimeNow       TimeNowFunc
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	// StdinIsTerminal reports whether someone at a terminal can answer a
	// question on Stdin; nil means nobody can.
	StdinIsTerminal func() bool
	VersionInfo     VersionInfo
	// settings are the settings the commands use.
	settings AppSettings
}

// VersionInfo contains version information
type VersionInfo struct {
	Version string
	Commit  string
	Date    string
}

// AppSettings are the settings the app's commands use.
type AppSettings struct {
	// VaultPath is the vault's file, which an export never replaces.
	VaultPath string
	// KDF is the Argon2id settings encrypted exports use; zero means
	// kdf.Default().
	KDF              kdf.Params
	ClipboardTimeout time.Duration
}

// NewDefaultApp creates the app; each command opens the vault itself.
func NewDefaultApp(versionInfo VersionInfo, settings AppSettings) *App {
	return &App{
		settings:     settings,
		ExecLookPath: exec.LookPath,
		Exit:         os.Exit,
		ClipboardCopy: func(text string) error {
			return clipboard.CopyWithAutoClear(text, settings.ClipboardTimeout)
		},
		ClipboardCheck: func() error {
			_, err := clipboard.Find()
			return err
		},
		ClipboardCopyFor: func(text string, atLeast time.Duration) error {
			if settings.ClipboardTimeout <= 0 {
				return clipboard.Copy(text)
			}
			return clipboard.CopyWithAutoClear(text, max(settings.ClipboardTimeout, atLeast))
		},
		ClipboardRead: clipboard.Read,
		TimeNow:       time.Now,
		Stdin:         os.Stdin,
		StdinIsTerminal: func() bool {
			return term.IsTerminal(int(os.Stdin.Fd()))
		},
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		VersionInfo: versionInfo,
	}
}

// ShowVersion displays version information
func (a *App) ShowVersion() error {
	_, err := fmt.Fprintf(a.Stdout, "sesh version %s (%s) built on %s\n",
		a.VersionInfo.Version, a.VersionInfo.Commit, a.VersionInfo.Date)
	return err
}

// errDeleteNeedsForce is a delete with nobody at a terminal to confirm it.
var errDeleteNeedsForce = errors.New("deleting asks first, and there's no terminal to ask at; add --force to delete without asking")

// confirmDelete names the entries a delete will remove and asks, at the
// terminal, whether to go ahead, saying when it's for good; with nobody
// there to answer, it refuses.
func (a *App) confirmDelete(ids []string, forGood bool) (bool, error) {
	if a.StdinIsTerminal == nil || !a.StdinIsTerminal() {
		return false, errDeleteNeedsForce
	}
	how := ""
	if forGood {
		how = " for good"
	}
	var b strings.Builder
	question := fmt.Sprintf("Delete %q%s? [y/N]: ", ids[0], how)
	if len(ids) > 1 {
		fmt.Fprintf(&b, "These entries will be deleted%s:\n", how)
		for _, id := range ids {
			fmt.Fprintf(&b, "  %s\n", id)
		}
		question = fmt.Sprintf("Delete these %s%s? [y/N]: ", entryCount(len(ids)), how)
	}
	if _, err := io.WriteString(a.Stderr, b.String()); err != nil {
		return false, err
	}
	return promptYesNo(a.Stdin, a.Stderr, question)
}

// GenerateCredentials gets credentials from p.
func (a *App) GenerateCredentials(p provider.ServiceProvider) error {
	serviceName := p.Name()
	if err := p.ValidateRequest(); err != nil {
		return err
	}

	quiet := isQuietProvider(p)

	if !quiet {
		if _, err := fmt.Fprintf(a.Stderr, "🔐 Generating credentials for %s...\n", serviceName); err != nil {
			return fmt.Errorf("failed to write to stderr: %w", err)
		}
	}
	startTime := time.Now()

	creds, err := p.GetCredentials()
	if err != nil {
		return fmt.Errorf("failed to generate credentials: %w", err)
	}

	if !quiet {
		elapsedTime := time.Since(startTime)
		if _, err := fmt.Fprintf(a.Stderr, "✅ Credentials acquired in %.2fs\n", elapsedTime.Seconds()); err != nil {
			return fmt.Errorf("failed to write to stderr: %w", err)
		}
	}

	return a.PrintCredentials(&creds)
}

// isQuietProvider reports whether p opts out of the generic action
// framing. Non-opting-in providers default to false.
func isQuietProvider(p provider.ServiceProvider) bool {
	qp, ok := p.(provider.QuietProvider)
	return ok && qp.SuppressActionFraming()
}

// insteadOfClip says how to get the value without a clipboard: --show,
// for a provider that has it, or the command without --clip, which prints
// it or uses it.
func insteadOfClip(p provider.ServiceProvider) string {
	for _, f := range p.GetFlagInfo() {
		if f.Name == "show" {
			return "use --show to print it instead"
		}
	}
	return "run it without --clip"
}

// CopyToClipboard copies p's code to the system clipboard.
func (a *App) CopyToClipboard(p provider.ServiceProvider) error {
	serviceName := p.Name()
	if err := p.ValidateRequest(); err != nil {
		return err
	}

	if cc, ok := p.(provider.ClipChecker); ok {
		if err := cc.CheckClip(); err != nil {
			return err
		}
	}
	if a.ClipboardCheck != nil {
		if err := a.ClipboardCheck(); err != nil {
			if errors.Is(err, clipboard.ErrNoDisplay) {
				return fmt.Errorf("can't copy: %w; %s", err, insteadOfClip(p))
			}
			return fmt.Errorf("can't copy: %w", err)
		}
	}

	quiet := isQuietProvider(p)

	if !quiet {
		if _, err := fmt.Fprintf(a.Stderr, "🔐 Generating credentials for %s...\n", serviceName); err != nil {
			return fmt.Errorf("failed to write to stderr: %w", err)
		}
	}
	startTime := time.Now()

	creds, err := p.GetClipboardValue()
	if err != nil {
		return fmt.Errorf("failed to generate credentials: %w", err)
	}

	elapsedTime := time.Since(startTime)

	if creds.CopyValue == "" {
		return fmt.Errorf("no content available to copy to clipboard")
	}

	if err := a.ClipboardCopy(creds.CopyValue); err != nil {
		return fmt.Errorf("failed to copy to clipboard: %w", err)
	}

	clipboardDesc := creds.ClipboardDescription
	if clipboardDesc == "" {
		clipboardDesc = "value"
	}

	if _, err := fmt.Fprintf(a.Stderr, "✅ %s copied to clipboard in %.2fs\n", clipboardDesc, elapsedTime.Seconds()); err != nil {
		return fmt.Errorf("failed to write to stderr: %w", err)
	}
	if _, err := fmt.Fprintf(a.Stderr, "%s\n", creds.DisplayInfo); err != nil {
		return fmt.Errorf("failed to write to stderr: %w", err)
	}

	return nil
}

// PrintCredentials outputs the credentials
func (a *App) PrintCredentials(creds *provider.Credentials) error {
	// Expiry is meaningful only for time-limited credentials (AWS session
	// tokens). Non-expiring results (passwords, stored secrets, imports)
	// leave Expiry as the zero value; skip the line entirely in that case
	// rather than printing "unknown".
	if !creds.Expiry.IsZero() {
		duration := creds.Expiry.Sub(a.TimeNow())
		formatted := creds.Expiry.Local().Format("2006-01-02 15:04:05")
		var expiryDisplay string
		if duration <= 0 {
			expiryDisplay = fmt.Sprintf("%s (expired)", formatted)
		} else {
			total := int(duration.Seconds())
			hours := total / 3600
			minutes := (total % 3600) / 60
			seconds := total % 60

			var validFor string
			switch {
			case hours > 0:
				validFor = fmt.Sprintf("%dh%dm", hours, minutes)
			case minutes > 0:
				validFor = fmt.Sprintf("%dm%ds", minutes, seconds)
			default:
				validFor = fmt.Sprintf("%ds", seconds)
			}
			expiryDisplay = fmt.Sprintf("%s (valid for %s)", formatted, validFor)
		}
		if _, err := fmt.Fprintf(a.Stderr, "⏳ Expires at: %s\n", expiryDisplay); err != nil {
			return fmt.Errorf("failed to write to stderr: %w", err)
		}
	}

	if creds.MFAAuthenticated {
		if _, err := fmt.Fprintf(a.Stderr, "✅ MFA-authenticated session established\n"); err != nil {
			return fmt.Errorf("failed to write to stderr: %w", err)
		}
	}

	if creds.DisplayInfo != "" {
		if _, err := fmt.Fprintf(a.Stderr, "%s\n", creds.DisplayInfo); err != nil {
			return fmt.Errorf("failed to write to stderr: %w", err)
		}
	}

	if creds.Value != "" {
		if _, err := fmt.Fprintln(a.Stdout, creds.Value); err != nil {
			return fmt.Errorf("failed to write to stdout: %w", err)
		}
	}

	// Shell-safe export commands go to stdout for eval/source
	// Built as a single string and written atomically so that callers using
	// eval "$(sesh ...)" never execute a partial env block.
	if len(creds.Variables) > 0 {
		lines := []string{"# --------- ENVIRONMENT VARIABLES ---------"}
		for key, value := range creds.Variables {
			if !validEnvVarName.MatchString(key) {
				if _, err := fmt.Fprintf(a.Stderr, "⚠️  Skipping invalid variable name: %q\n", key); err != nil {
					return fmt.Errorf("failed to write to stderr: %w", err)
				}
				continue
			}
			lines = append(lines, fmt.Sprintf("export %s='%s'", key, strings.ReplaceAll(value, "'", "'\\''")))
		}
		lines = append(lines, "# ----------------------------------------")
		if _, err := io.WriteString(a.Stdout, strings.Join(lines, "\n")+"\n"); err != nil {
			return fmt.Errorf("failed to write to stdout: %w", err)
		}
	}
	return nil
}

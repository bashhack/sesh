// Package setup provides sesh aws setup: storing an AWS profile's MFA key.
package setup

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	awsCLI "github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// The setup's contact with the world, variables so tests can replace them.
var (
	awsInstalled = func() error {
		_, err := exec.LookPath("aws")
		return err
	}
	callerIdentity             = awsCLI.CallerIdentity
	profileKind                = awsCLI.ProfileKind
	listMFADevices             = awsCLI.ListMFADevices
	readPassword               = term.ReadPassword
	scanQRCode                 = qrcode.ScanQRCodeFull
	readQRImage                = readTOTPImage
	validateAndNormalizeSecret = totp.ValidateAndNormalizeSecret
	stdinIsTerminal            = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	timeNow                    = time.Now
	// screenCapture says whether a QR code can be read off the screen:
	// macOS's screencapture does it.
	screenCapture = runtime.GOOS == "darwin"
	// homeDir is where a path typed from ~/ starts.
	homeDir = os.UserHomeDir
)

// readTOTPImage reads the TOTP QR code in the image file at path.
func readTOTPImage(path string) (qrcode.TOTPInfo, error) {
	_, info, err := qrcode.ReadTOTPFromFile(path)
	return info, err
}

// readLine reads a line of input, returning the trimmed string or an error.
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// askFiling asks where to file the entry the wizard is saving, unless
// filing already says. existing is the entry being replaced, nil for a new
// one: Enter keeps its folder and adds no tags. An answer no folder or tag
// can have is asked again, and the end of input saves with what was
// answered, since the secret is already captured.
func askFiling(r *bufio.Reader, filing vault.Filing, existing *vault.Entry) (vault.Filing, error) {
	if !filing.IsZero() {
		return filing, nil
	}
	var folder string
	var tags []string
	if existing != nil {
		folder, tags = existing.Folder, existing.Tags
	}
	fmt.Println()
	for {
		if folder == "" {
			fmt.Print("Folder (optional, such as work/aws; Enter for none): ")
		} else {
			fmt.Printf("Folder (Enter keeps %s): ", folder)
		}
		answer, end, err := readOptional(r)
		if err != nil {
			return vault.Filing{}, err
		}
		if answer != "" {
			if err := vault.CheckFolder(answer); err != nil {
				if !end {
					fmt.Printf("❌ %v\n", err)
					continue
				}
				fmt.Printf("❌ %v; saving without a folder\n", err)
			} else {
				filing.Folder, filing.FolderSet = answer, true
			}
		}
		if end {
			return filing, nil
		}
		break
	}
	for {
		if len(tags) == 0 {
			fmt.Print("Tags (optional, separated by spaces; Enter for none): ")
		} else {
			fmt.Printf("Tags to add (it has %s; Enter adds none): ", strings.Join(tags, " "))
		}
		answer, end, err := readOptional(r)
		if err != nil {
			return vault.Filing{}, err
		}
		filing.Tags = strings.Fields(answer)
		if err := filing.Check(); err != nil {
			if !end {
				fmt.Printf("❌ %v\n", err)
				continue
			}
			fmt.Printf("❌ %v; saving without tags\n", err)
			filing.Tags = nil
		}
		return filing, nil
	}
}

// readOptional reads the answer to an optional question; end reports that
// input ended with it, so nothing more can be asked.
func readOptional(r *bufio.Reader) (answer string, end bool, err error) {
	line, err := r.ReadString('\n')
	if errors.Is(err, io.EOF) {
		fmt.Println()
		return strings.TrimSpace(line), true, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("failed to read input: %w", err)
	}
	return strings.TrimSpace(line), false, nil
}

// AWSSetupHandler is sesh aws setup.
type AWSSetupHandler struct {
	store  vault.Store
	reader *bufio.Reader
}

// NewAWSSetupHandler creates a new AWS setup handler
func NewAWSSetupHandler(store vault.Store) *AWSSetupHandler {
	return &AWSSetupHandler{
		store:  store,
		reader: bufio.NewReader(os.Stdin),
	}
}

// profileName is how a profile is named in what the setup says.
func profileName(profile string) string {
	if profile == "" {
		return "the default profile"
	}
	return "profile " + profile
}

// Preflight checks what setup needs before anything else, so the vault
// isn't opened (or made) for a setup that can't run: a terminal, and the
// AWS CLI.
func Preflight() error {
	if !stdinIsTerminal() {
		return errors.New("sesh aws setup asks questions and reads the MFA key at a terminal: run it in one")
	}
	if err := awsInstalled(); err != nil {
		return errors.New("the AWS CLI isn't installed, and sesh aws uses it: https://aws.amazon.com/cli/")
	}
	return nil
}

// historyKeeper is a store that keeps entries' earlier secrets, as many as
// HistoryKeep says.
type historyKeeper interface{ HistoryKeep() int }

// keepsHistory says whether store keeps a replaced key in the entry's
// history.
func keepsHistory(store vault.Store) bool {
	h, ok := store.(historyKeeper)
	return ok && h.HistoryKeep() > 0
}

// Setup stores an AWS profile's MFA key, and the MFA device it's for:
//  1. it checks the AWS CLI is there, and who the profile signs in as;
//  2. it reads the key AWS shows for a new authenticator app: typed, or
//     from a QR code in an image file or on screen (macOS);
//  3. it saves the key, before AWS is told of it, so nothing that goes
//     wrong after (the agent locking while you're at the AWS console,
//     input ending) can lose a key AWS has started using;
//  4. it gives the two codes the AWS console asks for;
//  5. it finds the device AWS made, and saves it with the key, with the
//     entry's folder and tags.
//
// profile is --profile or AWS_PROFILE; "" asks, Enter taking the default.
func (h *AWSSetupHandler) Setup(profile string, filing vault.Filing) error {
	if err := Preflight(); err != nil {
		return err
	}
	fmt.Println("🔐 Setting up AWS MFA for sesh")

	if profile == "" {
		fmt.Print("AWS CLI profile (Enter for the default profile): ")
		var err error
		if profile, err = readLine(h.reader); err != nil {
			return err
		}
	}
	// Checked before anything else is asked, so a bad name doesn't cost
	// the whole setup.
	if err := vault.CheckName("AWS profile", profile); err != nil {
		return err
	}
	k := vault.AWSKey(profile)
	if err := k.Validate(); err != nil {
		return err
	}
	if kind := profileKind(profile); kind != "" {
		return fmt.Errorf("%s signs in with %s, which gives temporary credentials, and AWS gives MFA sessions only to an IAM user's own access keys: sesh aws setup is for a profile with those", profileName(profile), kind)
	}
	existing, err := existingEntry(h.store, k)
	if err != nil {
		return err
	}
	keeps := keepsHistory(h.store)
	if existing != nil {
		fmt.Printf("\n⚠️  sesh already has an MFA key for %s.\n", profileName(profile))
		if !keeps {
			fmt.Println("history.keep is 0, so the key it has now won't be kept: if AWS doesn't finish adding the new device, the old key is gone.")
		}
		fmt.Print("Replace it? (y/N): ")
		response, err := readLine(h.reader)
		if err != nil {
			return err
		}
		if r := strings.ToLower(response); r != "y" && r != "yes" {
			fmt.Printf("Nothing changed: the MFA key for %s is as it was.\n", profileName(profile))
			return nil
		}
	}

	identity, err := callerIdentity(profile)
	if err != nil {
		return fmt.Errorf("AWS couldn't say who %s signs in as, so sesh can't set it up: %w\nCheck the profile works with: aws sts get-caller-identity%s", profileName(profile), err, profileFlag(profile))
	}
	if strings.Contains(identity, ":assumed-role/") || strings.Contains(identity, ":federated-user/") {
		return fmt.Errorf("%s signs in as %s, a temporary session (such as SSO or a role); sesh aws needs a profile with an IAM user's own access keys, which AWS gives MFA sessions to", profileName(profile), identity)
	}
	fmt.Printf("✅ %s signs in as %s\n", strings.ToUpper(profileName(profile)[:1])+profileName(profile)[1:], identity)

	secret, err := h.captureSecret()
	if err != nil {
		return err
	}
	defer secure.SecureZeroBytes(secret)

	entry := vault.Entry{Key: k}
	if existing != nil {
		entry = *existing
		entry.UpdatedAt = time.Time{}
	}
	entry.Settings = vault.Settings{} // the device is found below
	filing.Apply(&entry)
	if err := h.store.Save(&entry, secret); err != nil {
		return fmt.Errorf("failed to store the MFA key: %w", err)
	}
	fmt.Printf("🔒 Saved the MFA key in the vault, as %s\n", k)

	inHistory := existing != nil && keeps
	if err := h.setupMFAConsole(secret); err != nil {
		return h.keyOnly(k, inHistory, err)
	}
	device, err := h.selectMFADevice(profile, awsCLI.AccountOf(identity))
	if err != nil {
		return h.keyOnly(k, inHistory, err)
	}
	if filing, err = askFiling(h.reader, filing, existing); err != nil {
		return h.keyOnly(k, inHistory, err)
	}
	entry.Settings = vault.Settings{AWSMFADevice: device}
	filing.Apply(&entry)
	if err := h.store.Save(&entry, secret); err != nil {
		return h.keyOnly(k, inHistory, fmt.Errorf("failed to store the MFA device: %w", err))
	}

	h.showSetupCompletionMessage(profile)
	return nil
}

// keyOnly is err from a setup that saved the key but not its device:
// what's kept, and what to do. inHistory says the key replaced is in the
// entry's history.
func (h *AWSSetupHandler) keyOnly(k vault.Key, inHistory bool, err error) error {
	msg := fmt.Sprintf("%v\nThe MFA key is saved, as %s, but not which MFA device it's for: sesh aws asks AWS for it when the user has one authenticator app; otherwise run sesh aws setup again to choose it.", err, k)
	if inHistory {
		msg += fmt.Sprintf("\nIf AWS didn't finish adding the device, the key this one replaced is in the entry's history: sesh history %s", shell.Quote(k.String()))
	}
	return errors.New(msg)
}

// profileFlag is --profile P for a named profile, to add to a command.
func profileFlag(profile string) string {
	if profile == "" {
		return ""
	}
	return " --profile " + shell.Quote(profile)
}

// captureSecret reads the MFA key AWS shows for a new authenticator app,
// asking again until it's one: typed, or from a QR code. The caller zeroes
// the key.
func (h *AWSSetupHandler) captureSecret() ([]byte, error) {
	fmt.Println(`
In the AWS console (https://console.aws.amazon.com):
  1. Go to IAM, then Users, your user, and Security credentials.
  2. Under "Multi-factor authentication (MFA)", choose "Assign MFA device".
  3. Name it, choose "Authenticator app", and choose Next.
  4. Leave that page open: sesh reads its key, then gives you the two
     codes it asks for. Don't choose "Add MFA" yet.`)
	choices := "1-2"
	if screenCapture {
		choices = "1-3"
	}
	for {
		fmt.Println(`
How should sesh read the key?
  1: Type or paste it (on that page, choose "Show secret key")
  2: Read the QR code from an image file (a screenshot of it)`)
		if screenCapture {
			fmt.Println("  3: Select the QR code on screen")
		}
		fmt.Printf("Choice (%s): ", choices)
		choice, err := readLine(h.reader)
		if err != nil {
			return nil, err
		}
		var raw []byte
		switch {
		case choice == "1":
			fmt.Print("Secret key (hidden as you type or paste it): ")
			raw, err = readPassword(syscall.Stdin)
			fmt.Println()
			if err != nil {
				return nil, fmt.Errorf("failed to read the secret key: %w", err)
			}
		case choice == "2":
			fmt.Print("Image file (a full path, or one starting with ~/): ")
			path, err := readLine(h.reader)
			if err != nil {
				return nil, err
			}
			if path, err = expandHome(path); err != nil {
				fmt.Printf("❌ %v\n", err)
				continue
			}
			info, err := readQRImage(path)
			if err != nil {
				fmt.Printf("❌ %v\n", err)
				continue
			}
			raw = []byte(info.Secret)
		case choice == "3" && screenCapture:
			fmt.Print("Press Enter, then drag across the QR code (Esc cancels)...")
			if _, err := readLine(h.reader); err != nil {
				return nil, err
			}
			info, err := scanQRCode()
			if err != nil {
				fmt.Printf("❌ %v\n", err)
				continue
			}
			raw = []byte(info.Secret)
		default:
			fmt.Printf("❌ Choose %s.\n", strings.Replace(choices, "-", " to ", 1))
			continue
		}
		normalized, err := validateAndNormalizeSecret(strings.TrimSpace(string(raw)))
		secure.SecureZeroBytes(raw)
		if err != nil {
			fmt.Printf("❌ That isn't a key sesh can make codes from: %v\n", err)
			continue
		}
		fmt.Println("✅ Read the key")
		return []byte(normalized), nil
	}
}

// expandHome is path with a leading ~/ made the home folder; another
// relative path is refused, since where it starts isn't clear.
func expandHome(path string) (string, error) {
	switch {
	case path == "":
		return "", errors.New("no file given")
	case strings.HasPrefix(path, "~/"):
		home, err := homeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[2:]), nil
	case !filepath.IsAbs(path):
		return "", fmt.Errorf("give a full path, or one starting with ~/, not %q", path)
	}
	return path, nil
}

// setupMFAConsole gives the two codes the AWS console asks for, and waits
// until AWS has the device; n makes new codes, for when AWS says the first
// ones are wrong (they were made too long before).
func (h *AWSSetupHandler) setupMFAConsole(secret []byte) error {
	for {
		first, second, err := totp.GenerateConsecutiveCodesForTimeBytes(secret, timeNow())
		if err != nil {
			return fmt.Errorf("failed to make the codes: %w", err)
		}
		fmt.Printf(`
The two codes AWS asks for:
  MFA code 1: %s
  MFA code 2: %s
Enter them, choose "Add MFA", and wait for AWS to say the device was added.
Then press Enter here (or n, and Enter, for new codes if AWS says these are wrong): `, first, second)
		answer, err := readLine(h.reader)
		if err != nil {
			return err
		}
		if !strings.EqualFold(answer, "n") {
			return nil
		}
	}
}

// selectMFADevice finds the device AWS made for the key: chosen from the
// authenticator apps AWS lists for the user, or typed. account is the
// profile's account, which a typed device has to be in.
func (h *AWSSetupHandler) selectMFADevice(profile, account string) (string, error) {
	for {
		devices, err := listMFADevices(profile)
		if err != nil {
			fmt.Printf("\n❌ sesh couldn't list the user's MFA devices: %v\n", err)
			return h.promptForMFAARN(account)
		}
		if len(devices) == 0 {
			fmt.Print("\nAWS lists no authenticator app for this user yet; it can take a few seconds after \"Add MFA\".\nPress Enter to look again, or m and Enter to type the device's ARN: ")
			answer, err := readLine(h.reader)
			if err != nil {
				return "", err
			}
			if strings.EqualFold(answer, "m") {
				return h.promptForMFAARN(account)
			}
			continue
		}
		fmt.Println("\nThe user's authenticator apps in AWS:")
		for i, d := range devices {
			fmt.Printf("  %d: %s\n", i+1, d)
		}
		for {
			fmt.Printf("Choose the one you just added (%s), r to look again, or m to type its ARN: ", numbers(len(devices)))
			answer, err := readLine(h.reader)
			if err != nil {
				return "", err
			}
			var n int
			switch _, scanErr := fmt.Sscanf(answer, "%d", &n); {
			case strings.EqualFold(answer, "r"):
			case strings.EqualFold(answer, "m"):
				return h.promptForMFAARN(account)
			case scanErr == nil && fmt.Sprint(n) == answer && n >= 1 && n <= len(devices):
				fmt.Printf("✅ MFA device: %s\n", devices[n-1])
				return devices[n-1], nil
			default:
				fmt.Printf("❌ Choose %s, r or m.\n", strings.Replace(numbers(len(devices)), "-", " to ", 1))
				continue
			}
			break // r: look again
		}
	}
}

// numbers is 1-n, or 1 when n is 1.
func numbers(n int) string {
	if n == 1 {
		return "1"
	}
	return fmt.Sprintf("1-%d", n)
}

// promptForMFAARN asks for the device's ARN until it's an authenticator
// app's, in account (when it's known).
func (h *AWSSetupHandler) promptForMFAARN(account string) (string, error) {
	example := "arn:aws:iam::ACCOUNT:mfa/NAME"
	if account != "" {
		example = "arn:aws:iam::" + account + ":mfa/NAME"
	}
	for {
		fmt.Printf("MFA device ARN (%s): ", example)
		arn, err := readLine(h.reader)
		if err != nil {
			return "", err
		}
		switch {
		case !awsCLI.IsVirtualMFADevice(arn):
			fmt.Println("❌ That isn't an authenticator app's ARN: it's shown on the user's Security credentials page, under MFA.")
		case account != "" && awsCLI.AccountOf(arn) != account:
			fmt.Printf("❌ That device is in account %s, but the profile signs in to account %s.\n", awsCLI.AccountOf(arn), account)
		default:
			return arn, nil
		}
	}
}

// showSetupCompletionMessage says the setup is done, and how to use it.
func (h *AWSSetupHandler) showSetupCompletionMessage(profile string) {
	shellCmd, clipCmd := "sesh aws"+profileFlag(profile), "sesh aws"+profileFlag(profile)+" --clip"
	fmt.Printf("\n✅ AWS MFA is set up for %s.\n   %-*s  opens a shell with a session's credentials\n   %-*s  copies a code, for signing in to the AWS console\nAWS has just used the codes it was given: wait for the next one (up to 30 seconds) before the first sesh aws.\n",
		profileName(profile), len(clipCmd), shellCmd, len(clipCmd), clipCmd)
}

// existingEntry returns the entry store holds at k, or nil when there's none.
func existingEntry(store vault.Store, k vault.Key) (*vault.Entry, error) {
	e, err := store.Lookup(k)
	switch {
	case err == nil:
		return &e, nil
	case errors.Is(err, vault.ErrNotFound):
		return nil, nil
	default:
		return nil, fmt.Errorf("failed to check for an existing entry: %w", err)
	}
}

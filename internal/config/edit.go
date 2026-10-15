package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/bashhack/sesh/internal/atomicfile"
)

// quoted are the settings the config file has as strings; the rest are
// whole numbers, or switches.
var quoted = map[string]bool{
	"db_path": true, "clipboard_timeout": true, "agent.idle_timeout": true, "agent.max_lifetime": true,
	"master_password.memory": true, "backup.dir": true,
}

// switches are the settings that are on or off: true or false.
var switches = map[string]bool{"ui.lock_on_quit": true, "agent.lock_on_sleep": true, "agent.lock_on_screen_lock": true}

// header is a table's header line: [name], perhaps with a comment.
var header = regexp.MustCompile(`^\s*\[\s*([A-Za-z0-9_.-]+)\s*\]\s*(#.*)?$`)

// Set writes key = value into the config file at path, keeping its other
// lines, their comments and order; value "" takes the key out, so its
// default applies. The file after must load as sesh loads it, with the
// key read from it: otherwise it's an error, and the file is left as it
// was. A file that isn't there yet is made.
func Set(path, key, value string) error {
	if _, ok := quoted[key]; !ok && !isNumberKey(key) && !switches[key] {
		return fmt.Errorf("%s isn't a setting sesh changes", key)
	}
	// The file a link (a dotfile manager's) points at is the one changed.
	path, err := resolveLinks(path)
	if err != nil {
		return err
	}
	old, err := os.ReadFile(path) //nolint:gosec // the user's config file
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	line := ""
	switch {
	case value == "":
	case quoted[key]:
		line = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
	case switches[key]:
		if value != "true" && value != "false" {
			return fmt.Errorf("%s = %q: want true or false", key, value)
		}
		line = value
	default:
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("%s = %q: want a whole number", key, value)
		}
		// As a number is written: 03 and +3 are 3.
		line = strconv.FormatInt(n, 10)
	}
	updated := setLine(string(old), key, line)
	if updated == string(old) {
		return nil // nothing to change
	}
	if err := checkSet(path, string(old), updated, key, value != ""); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("make %s: %w", filepath.Dir(path), err)
	}
	return atomicfile.Write(path, []byte(updated), mode)
}

// IsSwitch reports whether key is a setting that's on or off.
func IsSwitch(key string) bool { return switches[key] }

// IsNumber reports whether key is a setting whose value is a whole number.
func IsNumber(key string) bool { return isNumberKey(key) }

func isNumberKey(key string) bool {
	switch key {
	case "audit.retention_days", "master_password.time", "master_password.threads", "backup.every_days", "backup.keep",
		"trash.keep_days", "history.keep", "health.old_after_days":
		return true
	}
	return false
}

// checkSet loads content as the config file would be, and checks key is
// read from it (set) or isn't (not set), and every other setting is as it
// was in the file before, old.
func checkSet(path, old, content, key string, set bool) error {
	before, err := loadText(path, old)
	if err != nil {
		before = nil // a file that didn't load before: only the after is checked
	}
	after, err := loadText(path, content)
	if err != nil {
		return err
	}
	was := map[string]Item{}
	for _, it := range before {
		was[it.Key] = it
	}
	for _, it := range after {
		switch {
		case it.Key == key && (it.Source == FromFile) != set:
			return fmt.Errorf("%s couldn't be changed in %s as it's written there; edit the file yourself", key, path)
		case it.Key != key && before != nil && (was[it.Key].Source != it.Source || was[it.Key].Raw != it.Raw):
			return fmt.Errorf("changing %s would change %s too, as %s is written; edit the file yourself", key, it.Key, path)
		}
	}
	return nil
}

// loadText is the settings a config file holding content gives, path the
// file named in what's said.
func loadText(path, content string) ([]Item, error) {
	tmp, err := os.CreateTemp("", "sesh-config-*.toml")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // a temp file
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close() //nolint:errcheck,gosec // already failing
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	c, err := defaults(tmp.Name())
	if err != nil {
		return nil, err
	}
	if err := c.applyFile(); err != nil {
		return nil, errors.New(strings.ReplaceAll(err.Error(), tmp.Name(), path))
	}
	return c.List(), nil
}

// setLine is the file's text with key's line set to key = value (a TOML
// value, written as is), or taken out when value is "". It changes only
// that line, or adds one, with the file's line ends: in the key's table,
// after its last line, or a new table at the end; a key outside any table
// goes before the first table and the comments just above it.
func setLine(text, key, value string) string {
	table, name, inTable := strings.CutLast(key, ".")
	if !inTable {
		table, name = "", key
	}
	eol := "\n"
	if strings.Contains(text, "\r\n") {
		eol = "\r\n"
	}
	lines := strings.SplitAfter(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	// What each line says, without its line end, or a mark before the first.
	bare := func(i int) string {
		l := strings.TrimRight(lines[i], "\r\n")
		if i == 0 {
			l = strings.TrimPrefix(l, "\uFEFF")
		}
		return l
	}
	keyLine := regexp.MustCompile(`^(\s*` + regexp.QuoteMeta(name) + `\s*=\s*)`)
	dotted := regexp.MustCompile(`^(\s*` + regexp.QuoteMeta(key) + `\s*=\s*)`)
	current, lastInTable, tableAt, firstTable, lastTop := "", -1, -1, -1, -1
	for i := range lines {
		l := bare(i)
		if m := header.FindStringSubmatch(l); m != nil {
			current = m[1]
			if firstTable < 0 {
				firstTable = i
			}
			if current == table {
				tableAt, lastInTable = i, i
			}
			continue
		}
		var m []string
		switch {
		case current == table:
			m = keyLine.FindStringSubmatch(l)
		case current == "" && table != "":
			m = dotted.FindStringSubmatch(l)
		}
		if m != nil {
			if value == "" {
				return strings.Join(append(lines[:i:i], lines[i+1:]...), "")
			}
			start := len(lines[i]) - len(strings.TrimRight(lines[i], "\r\n"))
			end := lines[i][len(lines[i])-start:]
			lead := lines[i][:len(lines[i])-start-len(l)] // a mark before the first line
			lines[i] = lead + m[1] + value + afterValue(l[len(m[1]):]) + end
			return strings.Join(lines, "")
		}
		if strings.TrimSpace(l) != "" && !strings.HasPrefix(strings.TrimSpace(l), "#") {
			if current == table {
				lastInTable = i
			}
			if firstTable < 0 {
				lastTop = i
			}
		}
	}
	if value == "" {
		return text
	}
	add := name + " = " + value + eol
	// insert puts add before line at, ending the line before it first; a
	// byte order mark stays the file's first.
	insert := func(at int) string {
		if at > 0 && !strings.HasSuffix(lines[at-1], "\n") {
			lines[at-1] += eol
		}
		if rest, ok := strings.CutPrefix(lines[0], "\uFEFF"); at == 0 && ok {
			lines[0], add = rest, "\uFEFF"+add
		}
		return strings.Join(append(append(lines[:at:at], add), lines[at:]...), "")
	}
	switch {
	case table == "" && lastTop >= 0:
		return insert(lastTop + 1) // after the keys outside any table
	case table == "" && firstTable >= 0:
		// Before the first table and the comments right above it, not the
		// file's opening ones, a blank line apart.
		at := firstTable
		for at > 0 && strings.HasPrefix(strings.TrimSpace(bare(at-1)), "#") {
			at--
		}
		return insert(at)
	case table == "":
		return ensureNewline(text, eol) + add
	case tableAt >= 0:
		return insert(lastInTable + 1)
	}
	sep := ""
	if strings.TrimSpace(text) != "" {
		sep = eol
	}
	return ensureNewline(text, eol) + sep + "[" + table + "]" + eol + add
}

// afterValue is what follows a value on its line: its comment, spaces
// and line end, with the value itself left out.
func afterValue(rest string) string {
	end := 0
	switch {
	case strings.HasPrefix(rest, `"`):
		for end = 1; end < len(rest); end++ {
			if rest[end] == '\\' {
				end++
				continue
			}
			if rest[end] == '"' {
				end++
				break
			}
		}
	case strings.HasPrefix(rest, "'"):
		if i := strings.Index(rest[1:], "'"); i >= 0 {
			end = i + 2
		}
	default:
		end = strings.IndexAny(rest, "#\n")
		if end < 0 {
			end = len(rest)
		}
		for end > 0 && (rest[end-1] == ' ' || rest[end-1] == '\t' || rest[end-1] == '\r') {
			end--
		}
	}
	return rest[min(end, len(rest)):]
}

func ensureNewline(text, eol string) string {
	if text != "" && !strings.HasSuffix(text, "\n") {
		return text + eol
	}
	return text
}

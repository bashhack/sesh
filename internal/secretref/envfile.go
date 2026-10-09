package secretref

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// EnvVar is a variable for a command's environment: a plain value, or a
// reference to resolve.
type EnvVar struct {
	Ref   *Ref
	Name  string
	Value string
}

// ParseEnvFlag reads --env's NAME=value, where value may be a reference.
func ParseEnvFlag(s string) (EnvVar, error) {
	name, value, ok := strings.Cut(s, "=")
	if !ok {
		return EnvVar{}, fmt.Errorf("--env wants NAME=value, not %q", s)
	}
	return envVar(name, value)
}

// ParseEnvFile reads an env file, called name in errors: one NAME=value
// per line. A line starting with # is a comment, as is a # after a space
// following a value not in quotes; blank lines are skipped. "export" may
// come before the name; a value in single or double quotes has them taken
// off; nothing is expanded. A value starting with sesh:// is a reference.
func ParseEnvFile(r io.Reader, name string) ([]EnvVar, error) {
	var vars []EnvVar
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if n == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "export"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			line = strings.TrimSpace(rest)
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s line %d: want NAME=value", name, n)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch {
		case v != "" && (v[0] == '"' || v[0] == '\''):
			end := strings.IndexByte(v[1:], v[0])
			if end < 0 {
				return nil, fmt.Errorf("%s line %d: the quote isn't closed", name, n)
			}
			// Only spaces, and a comment, can follow the closing quote.
			if after := strings.TrimSpace(v[end+2:]); after != "" && !strings.HasPrefix(after, "#") {
				hint := ""
				if strings.HasSuffix(v[:end+1], "\\") {
					hint = ` (a \ doesn't escape a quote here; use the other kind of quote around the value)`
				}
				return nil, fmt.Errorf("%s line %d: text after the closing quote: %q%s", name, n, after, hint)
			}
			v = v[1 : end+1]
		default:
			// A # after a space starts a comment, as in other env files.
			if i := strings.Index(v, " #"); i >= 0 {
				v = strings.TrimSpace(v[:i])
			} else if i := strings.Index(v, "\t#"); i >= 0 {
				v = strings.TrimSpace(v[:i])
			}
		}
		ev, err := envVar(k, v)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", name, n, err)
		}
		if seen[k] {
			return nil, fmt.Errorf("%s line %d: %s is set twice", name, n, k)
		}
		seen[k] = true
		vars = append(vars, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return vars, nil
}

// envVar is the variable name=value, with value read as a reference when
// it starts with sesh://.
func envVar(name, value string) (EnvVar, error) {
	if !isEnvName(name) {
		return EnvVar{}, fmt.Errorf("%q isn't a variable name: use letters, digits and _, not starting with a digit", name)
	}
	if !strings.HasPrefix(value, Prefix) {
		return EnvVar{Name: name, Value: value}, nil
	}
	r, err := Parse(value)
	if err != nil {
		return EnvVar{}, err
	}
	return EnvVar{Name: name, Ref: &r}, nil
}

func isEnvName(s string) bool {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for _, c := range s {
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

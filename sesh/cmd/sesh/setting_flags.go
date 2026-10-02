package main

import (
	"fmt"
	"strings"

	"github.com/bashhack/sesh/internal/config"
)

// settingFlags are the global flags that override a setting for one run.
// They're taken out of the arguments before anything else parses them,
// because the store is opened, with these settings, before the command's
// own flags are read.
var settingFlags = map[string]func(*config.Overrides, string){
	"backend":    func(o *config.Overrides, v string) { o.Backend = v },
	"key-source": func(o *config.Overrides, v string) { o.KeySource = v },
	"db-path":    func(o *config.Overrides, v string) { o.DBPath = v },
}

// takeSettingFlags removes --backend, --key-source, and --db-path (with one
// or two dashes, as "--flag value" or "--flag=value") from args and returns
// the rest with the overrides they set. Arguments after "--" are left alone.
func takeSettingFlags(args []string) ([]string, config.Overrides, error) {
	var o config.Overrides
	if len(args) == 0 {
		return args, o, nil
	}
	rest := []string{args[0]}
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		set, ok := settingFlags[name]
		if !ok || !strings.HasPrefix(a, "-") {
			rest = append(rest, a)
			continue
		}
		if !hasValue {
			if i+1 >= len(args) {
				return nil, o, fmt.Errorf("--%s needs a value", name)
			}
			value = args[i+1] //nolint:gosec // bounds checked just above
			i++
		}
		if value == "" {
			return nil, o, fmt.Errorf("--%s needs a value", name)
		}
		set(&o, value)
	}
	return rest, o, nil
}

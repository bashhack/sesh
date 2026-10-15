package config

import (
	"fmt"
	"strconv"
)

// Loss is what changing key from from to to deletes for good, in words;
// "" when nothing. Each of these keeps everything at 0, so only a smaller
// number deletes.
func Loss(key, from, to string) string {
	f, ferr := strconv.Atoi(from)
	t, terr := strconv.Atoi(to)
	if ferr != nil || terr != nil || t <= 0 || (f > 0 && t >= f) {
		return ""
	}
	days := fmt.Sprintf("%d days", t)
	if t == 1 {
		days = "1 day"
	}
	switch key {
	case "history.keep":
		return fmt.Sprintf("Each entry's earlier secrets beyond its newest %d will be deleted for good, the next time a command unlocks the vault.", t)
	case "trash.keep_days":
		return fmt.Sprintf("Entries in the trash for more than %s will be deleted for good, the next time a command unlocks the vault.", days)
	case "audit.retention_days":
		return fmt.Sprintf("Audit log events older than %s will be deleted, the next time a command unlocks the vault.", days)
	case "backup.keep":
		return fmt.Sprintf("Backups beyond the newest %d will be deleted at the next backup.", t)
	}
	return ""
}

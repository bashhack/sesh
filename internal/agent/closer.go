package agent

import (
	"fmt"
	"io"
	"os"
)

// closeOrLog closes c, surfacing any error as a stderr warning. Used in
// defer chains where the close failure isn't actionable (the primary
// path already errored) but we don't want to silently swallow it either.
func closeOrLog(c io.Closer, what string) {
	if err := c.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: close %s: %v\n", what, err) //nolint:errcheck // best-effort warning to stderr
	}
}

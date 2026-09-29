package agent

import (
	"errors"
	"testing"
)

// errCloser is a test io.Closer that returns a configurable error.
type errCloser struct {
	err error
}

func (c *errCloser) Close() error { return c.err }

func TestCloseOrLog_SilentOnSuccess(t *testing.T) {
	// Just confirming the function runs without panic when Close
	// succeeds; closeOrLog has no return so there's nothing else to
	// assert here without capturing stderr.
	closeOrLog(&errCloser{err: nil}, "noop")
}

func TestCloseOrLog_SurvivesCloseError(t *testing.T) {
	// closeOrLog must not panic or propagate when Close errors; the
	// warning goes to stderr.
	closeOrLog(&errCloser{err: errors.New("boom")}, "noop")
}

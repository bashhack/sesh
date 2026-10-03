//go:build !darwin || !cgo

package touchid

func available() bool { return false }

func newKey() (blob, pub []byte, err error) { return nil, nil, ErrUnavailable }

func nativeSharedSecret(_, _ []byte, _ string) ([]byte, error) { return nil, ErrUnavailable }

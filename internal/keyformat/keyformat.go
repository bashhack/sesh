// Package keyformat provides a single convention for building and parsing
// keychain service keys. All keys follow the format:
//
//	{namespace}/{segment1}[/{segment2}]...
//
// The namespace is a fixed dash-delimited prefix (e.g. "sesh-aws",
// "sesh-totp"). Segments are variable components separated by "/".
// Segments must not contain "/" — this is validated at build time so
// that the delimiter is always unambiguous.
package keyformat

import (
	"fmt"
	"strings"
)

// Build constructs a service key from a namespace and variable segments.
// It returns an error if any segment is empty or contains "/".
func Build(namespace string, segments ...string) (string, error) {
	for _, seg := range segments {
		if seg == "" {
			return "", fmt.Errorf("keyformat: segment must not be empty")
		}
		if strings.Contains(seg, "/") {
			return "", fmt.Errorf("keyformat: segment %q must not contain '/'", seg)
		}
	}
	if len(segments) == 0 {
		return namespace, nil
	}
	return namespace + "/" + strings.Join(segments, "/"), nil
}

// MustBuild is like Build but panics on invalid input.
// Use only when segments are known-safe constants.
func MustBuild(namespace string, segments ...string) string {
	key, err := Build(namespace, segments...)
	if err != nil {
		panic(err)
	}
	return key
}

// Parse splits a service key into its variable segments after stripping
// the namespace prefix and the "/" separator. It returns an error if the
// key does not begin with the expected namespace prefix.
func Parse(key, namespace string) ([]string, error) {
	if key == namespace {
		return nil, nil
	}
	prefix := namespace + "/"
	if !strings.HasPrefix(key, prefix) {
		return nil, fmt.Errorf("keyformat: key %q does not match namespace %q", key, namespace)
	}
	remainder := key[len(prefix):]
	if remainder == "" {
		return nil, fmt.Errorf("keyformat: key %q has no segments after namespace", key)
	}
	segments := strings.Split(remainder, "/")
	for _, seg := range segments {
		if seg == "" {
			return nil, fmt.Errorf("keyformat: key %q contains empty segment", key)
		}
	}
	return segments, nil
}

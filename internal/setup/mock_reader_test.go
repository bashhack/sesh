package setup

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// mockReader wraps a strings.Reader and returns an error when out of input
// instead of returning empty strings forever
type mockReader struct {
	reader *strings.Reader
	bufReader *bufio.Reader
}

func newMockReader(input string) *mockReader {
	r := strings.NewReader(input)
	return &mockReader{
		reader: r,
		bufReader: bufio.NewReader(r),
	}
}

func (m *mockReader) ReadString(delim byte) (string, error) {
	line, err := m.bufReader.ReadString(delim)
	if err == io.EOF && line == "" {
		// Return a clear error when we're out of input
		return "", fmt.Errorf("mock reader: no more input available")
	}
	return line, err
}

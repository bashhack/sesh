package testutil

import (
	"crypto/rand"
	"encoding/base64"
	"math"
)

func RandomString(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}
	// Number of random bytes needed for length base64 characters
	numBytes := int(math.Ceil(float64(length) * 6.0 / 8.0))
	bytes := make([]byte, numBytes)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	b64 := base64.URLEncoding.EncodeToString(bytes)
	if len(b64) < length {
		return b64, nil // Shouldn't normally happen, but defensively return what we have
	}
	return b64[:length], nil
}

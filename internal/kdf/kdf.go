// Package kdf holds the Argon2id settings that turn a password into a key:
// the vault's master password and an encrypted export's password.
package kdf

import (
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Params are Argon2id's settings. They're stored with what they protect (the
// vault's key record, an export's envelope), so changing the configured
// ones never stops anything already made from opening.
type Params struct {
	Time    uint32 `json:"time"`    // passes over the memory
	Memory  uint32 `json:"memory"`  // KiB
	Threads uint8  `json:"threads"` // lanes computed in parallel
	KeyLen  uint32 `json:"key_len"` // derived key length in bytes
}

// The settings sesh uses unless configured otherwise: 256 MiB, 3 passes,
// 4 threads, a 32-byte (AES-256) key.
const (
	DefaultMemoryKiB = 256 * 1024
	DefaultTime      = 3
	DefaultThreads   = 4
	KeyLen           = 32
)

// The most an unlock or an import accepts, so a damaged or hostile record
// can't make sesh use unbounded memory or time; configured settings can't
// go above them either, so whatever sesh makes it can open.
const (
	MaxMemoryKiB = 1 << 20 // 1 GiB
	MaxTime      = 10
	MaxThreads   = 16
)

// The least that can be configured: OWASP's minimum for Argon2id (19 MiB,
// 2 passes, 1 thread). Lower would make guessing passwords cheap.
const (
	MinMemoryKiB = 19 * 1024
	MinTime      = 2
	MinThreads   = 1
)

// Default returns the settings sesh uses unless configured otherwise.
func Default() Params {
	return Params{Time: DefaultTime, Memory: DefaultMemoryKiB, Threads: DefaultThreads, KeyLen: KeyLen}
}

// Minimum returns the least settings that can be configured.
func Minimum() Params {
	return Params{Time: MinTime, Memory: MinMemoryKiB, Threads: MinThreads, KeyLen: KeyLen}
}

// CheckBounds refuses settings read from a vault or an export that are zero
// or above the maximums, or a key length other than KeyLen.
func (p Params) CheckBounds() error {
	if p.Memory == 0 || p.Memory > MaxMemoryKiB {
		return fmt.Errorf("memory setting out of range: %d KiB (max %d)", p.Memory, MaxMemoryKiB)
	}
	if p.Time == 0 || p.Time > MaxTime {
		return fmt.Errorf("time setting out of range: %d (max %d)", p.Time, MaxTime)
	}
	if p.Threads == 0 || p.Threads > MaxThreads {
		return fmt.Errorf("threads setting out of range: %d (max %d)", p.Threads, MaxThreads)
	}
	if p.KeyLen != KeyLen {
		return fmt.Errorf("key_len must be %d, got %d", KeyLen, p.KeyLen)
	}
	return nil
}

// MarshalParams serialises the settings to JSON. The fields are all
// fixed-width integers, so json.Marshal can't fail; a failure here is a
// programming bug.
func (p Params) MarshalParams() string {
	b, err := json.Marshal(p)
	if err != nil {
		panic(fmt.Sprintf("marshal kdf.Params: %v (unreachable: fields are all numeric)", err))
	}
	return string(b)
}

// Derive derives a key from password and salt with p.
func Derive(password, salt []byte, p Params) []byte {
	return argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
}

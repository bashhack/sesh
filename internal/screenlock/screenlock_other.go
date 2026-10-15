//go:build !darwin || !cgo

package screenlock

func locked0() (locked, known bool) { return false, false }

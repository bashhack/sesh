//go:build darwin && cgo

package screenlock

/*
#cgo LDFLAGS: -framework CoreGraphics -framework CoreFoundation
#include <CoreGraphics/CoreGraphics.h>
#include <CoreFoundation/CoreFoundation.h>

// sl_locked is 1 when the session's screen is locked, 0 when not, and -1
// with no session to ask (not in a login session).
static int sl_locked(void) {
	CFDictionaryRef d = CGSessionCopyCurrentDictionary();
	if (d == NULL) {
		return -1;
	}
	int out = 0;
	CFBooleanRef v = CFDictionaryGetValue(d, CFSTR("CGSSessionScreenIsLocked"));
	if (v != NULL && CFGetTypeID(v) == CFBooleanGetTypeID() && CFBooleanGetValue(v)) {
		out = 1;
	}
	CFRelease(d);
	return out;
}
*/
import "C"

func locked0() (locked, known bool) {
	switch C.sl_locked() {
	case 1:
		return true, true
	case 0:
		return false, true
	}
	return false, false
}

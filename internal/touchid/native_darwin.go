//go:build darwin && cgo

package touchid

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>
#include <string.h>

// tid_result carries bytes the caller frees, or an error.
typedef struct {
	unsigned char *data;
	int len;
	long code;
	char domain[96];
} tid_result;

static tid_result tid_error(CFErrorRef err) {
	tid_result r = {0};
	if (err == NULL) {
		r.code = -1;
		strlcpy(r.domain, "unknown", sizeof r.domain);
		return r;
	}
	r.code = CFErrorGetCode(err);
	CFStringGetCString(CFErrorGetDomain(err), r.domain, sizeof r.domain, kCFStringEncodingUTF8);
	CFRelease(err);
	return r;
}

static tid_result tid_bytes(CFDataRef d) {
	tid_result r = {0};
	r.len = (int)CFDataGetLength(d);
	r.data = r.len > 0 ? malloc(r.len) : NULL;
	if (r.data == NULL) {
		r.len = 0;
		r.code = -3;
		strlcpy(r.domain, "sesh: no bytes (empty result or out of memory)", sizeof r.domain);
		return r;
	}
	memcpy(r.data, CFDataGetBytePtr(d), r.len);
	return r;
}

static int tid_available(void) {
	LAContext *ctx = [[LAContext alloc] init];
	return [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:NULL] ? 1 : 0;
}

// tid_new_key creates a Secure Enclave P-256 key, not stored in the
// Keychain, that only a currently enrolled fingerprint can use. It returns
// the key's blob (its "toid", the same bytes as CryptoKit's
// dataRepresentation) and sets *pub to the uncompressed public key.
static tid_result tid_new_key(tid_result *pub) {
	@autoreleasepool {
		CFErrorRef err = NULL;
		SecAccessControlRef ac = SecAccessControlCreateWithFlags(NULL,
			kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
			kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet, &err);
		if (ac == NULL) return tid_error(err);
		NSDictionary *attrs = @{
			(id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
			(id)kSecAttrKeySizeInBits: @256,
			(id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
			(id)kSecPrivateKeyAttrs: @{
				(id)kSecAttrIsPermanent: @NO,
				(id)kSecAttrAccessControl: (__bridge id)ac,
			},
		};
		SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &err);
		CFRelease(ac);
		if (key == NULL) return tid_error(err);

		NSDictionary *got = CFBridgingRelease(SecKeyCopyAttributes(key));
		NSData *blob = got[@"toid"];
		SecKeyRef pubKey = SecKeyCopyPublicKey(key);
		CFDataRef pubBytes = pubKey ? SecKeyCopyExternalRepresentation(pubKey, &err) : NULL;
		if (pubKey) CFRelease(pubKey);
		CFRelease(key);
		if (blob == nil) {
			if (pubBytes) CFRelease(pubBytes);
			tid_result r = {0};
			r.code = -2;
			strlcpy(r.domain, "sesh: no key blob", sizeof r.domain);
			return r;
		}
		if (pubBytes == NULL) return tid_error(err);
		*pub = tid_bytes(pubBytes);
		CFRelease(pubBytes);
		return tid_bytes((__bridge CFDataRef)blob);
	}
}

// tid_shared_secret has the Secure Enclave key in blob do an ECDH with the
// uncompressed P-256 public key peer. The chip asks for a fingerprint,
// showing reason.
static tid_result tid_shared_secret(const void *blob, int blobLen, const void *peer, int peerLen, const char *reason) {
	@autoreleasepool {
		LAContext *ctx = [[LAContext alloc] init];
		ctx.localizedReason = [NSString stringWithUTF8String:reason];
		NSData *b = [NSData dataWithBytes:blob length:blobLen];
		NSDictionary *attrs = @{
			(id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
			(id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
			(id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
			@"toid": b,
			(id)kSecUseAuthenticationContext: ctx,
		};
		CFErrorRef err = NULL;
		SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)b, (__bridge CFDictionaryRef)attrs, &err);
		if (key == NULL) return tid_error(err);

		NSDictionary *pubAttrs = @{
			(id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
			(id)kSecAttrKeyClass: (id)kSecAttrKeyClassPublic,
		};
		NSData *p = [NSData dataWithBytes:peer length:peerLen];
		SecKeyRef peerKey = SecKeyCreateWithData((__bridge CFDataRef)p, (__bridge CFDictionaryRef)pubAttrs, &err);
		if (peerKey == NULL) {
			CFRelease(key);
			return tid_error(err);
		}
		CFDataRef shared = SecKeyCopyKeyExchangeResult(key, kSecKeyAlgorithmECDHKeyExchangeStandard,
			peerKey, (__bridge CFDictionaryRef)@{}, &err);
		CFRelease(peerKey);
		CFRelease(key);
		if (shared == NULL) return tid_error(err);
		tid_result r = tid_bytes(shared);
		CFRelease(shared);
		return r;
	}
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

func available() bool { return C.tid_available() == 1 }

func newKey() (blob, pub []byte, err error) {
	var p C.tid_result
	r := C.tid_new_key(&p)
	pub, err = take(&p)
	blob, berr := take(&r)
	if berr != nil {
		return nil, nil, berr
	}
	if err != nil {
		return nil, nil, err
	}
	return blob, pub, nil
}

func nativeSharedSecret(blob, peer []byte, reason string) ([]byte, error) {
	if len(blob) == 0 || len(peer) == 0 {
		return nil, errors.New("touch ID: empty key")
	}
	cr := C.CString(reason)
	defer C.free(unsafe.Pointer(cr))
	r := C.tid_shared_secret(unsafe.Pointer(&blob[0]), C.int(len(blob)),
		unsafe.Pointer(&peer[0]), C.int(len(peer)), cr)
	return take(&r)
}

// take copies a result's bytes into Go memory, zeroing and freeing the C
// copy, or converts its error.
func take(r *C.tid_result) ([]byte, error) {
	if r.data == nil {
		// Every native call returns bytes on success, so no bytes and no
		// error code is still a failure, never an empty success.
		if r.code == 0 {
			return nil, errors.New("touch ID: native call returned nothing")
		}
		return nil, classify(C.GoString(&r.domain[0]), int64(r.code))
	}
	b := C.GoBytes(unsafe.Pointer(r.data), r.len)
	C.memset(unsafe.Pointer(r.data), 0, C.size_t(r.len))
	C.free(unsafe.Pointer(r.data))
	return b, nil
}

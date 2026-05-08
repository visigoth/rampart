//go:build darwin

package ca

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <Security/SecTrustSettings.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/AuthSession.h>
#include <stdlib.h>
#include <string.h>

static CFStringRef const rampart_label = CFSTR("rampart CA");

// rampart_save_key stores an ECDSA P-256 private key from x9.63 bytes in Keychain.
// The key never touches disk (TR20). Returns OSStatus.
static int rampart_save_key(const uint8_t *x963, size_t x963Len) {
    CFDataRef keyData = CFDataCreate(kCFAllocatorDefault, x963, (CFIndex)x963Len);
    if (!keyData) return errSecMemoryError;

    int keySizeBits = 256;
    CFNumberRef keySizeNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &keySizeBits);

    const void *attrKeys[]   = { kSecAttrKeyType,                  kSecAttrKeyClass,      kSecAttrKeySizeInBits };
    const void *attrVals[]   = { kSecAttrKeyTypeECSECPrimeRandom,  kSecAttrKeyClassPrivate, keySizeNum };
    CFDictionaryRef attrs = CFDictionaryCreate(kCFAllocatorDefault, attrKeys, attrVals, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFErrorRef error = NULL;
    SecKeyRef keyRef = SecKeyCreateWithData(keyData, attrs, &error);
    CFRelease(keyData);
    CFRelease(keySizeNum);
    CFRelease(attrs);
    if (error) CFRelease(error);
    if (!keyRef) return errSecParam;

    // Force the file-backed login keychain — kSecClassKey items default to
    // the data-protection keychain on modern macOS, which requires the
    // keychain-access-groups entitlement that adhoc-signed binaries lack.
    // Without this, SecItemAdd fails with OSStatus -34018 (errSecMissingEntitlement).
    const void *addKeys[] = { kSecClass,    kSecValueRef, kSecAttrLabel, kSecAttrIsPermanent, kSecUseDataProtectionKeychain };
    const void *addVals[] = { kSecClassKey, keyRef,       rampart_label, kCFBooleanTrue,      kCFBooleanFalse };
    CFDictionaryRef addQ = CFDictionaryCreate(kCFAllocatorDefault, addKeys, addVals, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus st = SecItemAdd(addQ, NULL);
    CFRelease(addQ);
    CFRelease(keyRef);
    return (int)st;
}

// rampart_save_cert stores a DER-encoded cert in Keychain.
static int rampart_save_cert(const uint8_t *der, size_t derLen) {
    CFDataRef certData = CFDataCreate(kCFAllocatorDefault, der, (CFIndex)derLen);
    if (!certData) return errSecMemoryError;
    SecCertificateRef certRef = SecCertificateCreateWithData(kCFAllocatorDefault, certData);
    CFRelease(certData);
    if (!certRef) return errSecParam;

    const void *addKeys[] = { kSecClass,              kSecValueRef, kSecAttrLabel, kSecUseDataProtectionKeychain };
    const void *addVals[] = { kSecClassCertificate,   certRef,      rampart_label, kCFBooleanFalse };
    CFDictionaryRef addQ = CFDictionaryCreate(kCFAllocatorDefault, addKeys, addVals, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus st = SecItemAdd(addQ, NULL);
    CFRelease(addQ);
    CFRelease(certRef);
    return (int)st;
}

// rampart_set_trust sets user-domain trust for the stored cert (prompts for auth).
static int rampart_set_trust(void) {
    const void *sKeys[] = { kSecClass,             kSecAttrLabel, kSecReturnRef,  kSecMatchLimit,    kSecUseDataProtectionKeychain };
    const void *sVals[] = { kSecClassCertificate,  rampart_label, kCFBooleanTrue, kSecMatchLimitOne, kCFBooleanFalse };
    CFDictionaryRef sq = CFDictionaryCreate(kCFAllocatorDefault, sKeys, sVals, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef result = NULL;
    OSStatus st = SecItemCopyMatching(sq, &result);
    CFRelease(sq);
    if (st != errSecSuccess) return (int)st;
    SecCertificateRef certRef = (SecCertificateRef)result;
    st = SecTrustSettingsSetTrustSettings(certRef, kSecTrustSettingsDomainUser, NULL);
    CFRelease(certRef);
    return (int)st;
}

// rampart_load_key returns the stored SecKeyRef (caller must CFRelease).
static SecKeyRef rampart_load_key(void) {
    const void *sKeys[] = { kSecClass,    kSecAttrKeyClass,        kSecAttrLabel, kSecReturnRef,  kSecMatchLimit,    kSecUseDataProtectionKeychain };
    const void *sVals[] = { kSecClassKey, kSecAttrKeyClassPrivate, rampart_label, kCFBooleanTrue, kSecMatchLimitOne, kCFBooleanFalse };
    CFDictionaryRef sq = CFDictionaryCreate(kCFAllocatorDefault, sKeys, sVals, 6,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef result = NULL;
    SecItemCopyMatching(sq, &result);
    CFRelease(sq);
    return (SecKeyRef)result;
}

// rampart_load_cert_der returns cert DER bytes (caller must free *out with free()).
static int rampart_load_cert_der(uint8_t **out, size_t *outLen) {
    const void *sKeys[] = { kSecClass,            kSecAttrLabel, kSecReturnRef,  kSecMatchLimit,    kSecUseDataProtectionKeychain };
    const void *sVals[] = { kSecClassCertificate, rampart_label, kCFBooleanTrue, kSecMatchLimitOne, kCFBooleanFalse };
    CFDictionaryRef sq = CFDictionaryCreate(kCFAllocatorDefault, sKeys, sVals, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef result = NULL;
    OSStatus st = SecItemCopyMatching(sq, &result);
    CFRelease(sq);
    if (st != errSecSuccess) { *out = NULL; *outLen = 0; return (int)st; }
    SecCertificateRef certRef = (SecCertificateRef)result;
    CFDataRef certData = SecCertificateCopyData(certRef);
    CFRelease(certRef);
    if (!certData) { *out = NULL; *outLen = 0; return errSecParam; }
    CFIndex len = CFDataGetLength(certData);
    *out = (uint8_t *)malloc((size_t)len);
    if (*out) {
        CFDataGetBytes(certData, CFRangeMake(0, len), *out);
        *outLen = (size_t)len;
    } else {
        *outLen = 0;
        st = errSecMemoryError;
    }
    CFRelease(certData);
    return (int)st;
}

// rampart_remove_key deletes the stored key from Keychain.
static int rampart_remove_key(void) {
    const void *dKeys[] = { kSecClass,    kSecAttrKeyClass,        kSecAttrLabel, kSecMatchLimit,    kSecUseDataProtectionKeychain };
    const void *dVals[] = { kSecClassKey, kSecAttrKeyClassPrivate, rampart_label, kSecMatchLimitAll, kCFBooleanFalse };
    CFDictionaryRef dq = CFDictionaryCreate(kCFAllocatorDefault, dKeys, dVals, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus st = SecItemDelete(dq);
    CFRelease(dq);
    return (int)st;
}

// rampart_remove_cert removes trust settings and deletes the cert from Keychain.
static int rampart_remove_cert(void) {
    // Remove trust settings first.
    const void *sKeys[] = { kSecClass,            kSecAttrLabel, kSecReturnRef,  kSecMatchLimit,    kSecUseDataProtectionKeychain };
    const void *sVals[] = { kSecClassCertificate, rampart_label, kCFBooleanTrue, kSecMatchLimitOne, kCFBooleanFalse };
    CFDictionaryRef sq = CFDictionaryCreate(kCFAllocatorDefault, sKeys, sVals, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef result = NULL;
    if (SecItemCopyMatching(sq, &result) == errSecSuccess) {
        SecCertificateRef certRef = (SecCertificateRef)result;
        SecTrustSettingsRemoveTrustSettings(certRef, kSecTrustSettingsDomainUser);
        CFRelease(certRef);
    }
    CFRelease(sq);
    // Delete cert.
    const void *dKeys[] = { kSecClass,            kSecAttrLabel, kSecMatchLimit,    kSecUseDataProtectionKeychain };
    const void *dVals[] = { kSecClassCertificate, rampart_label, kSecMatchLimitAll, kCFBooleanFalse };
    CFDictionaryRef dq = CFDictionaryCreate(kCFAllocatorDefault, dKeys, dVals, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus st = SecItemDelete(dq);
    CFRelease(dq);
    return (int)st;
}

// rampart_sign signs a SHA-256 digest with the SecKeyRef using ECDSA X9.62.
// Returns 1 on success; *sigOut must be freed by caller.
static int rampart_sign(SecKeyRef keyRef, const uint8_t *digest, size_t digestLen,
                        uint8_t **sigOut, size_t *sigLen) {
    CFDataRef digestCF = CFDataCreate(kCFAllocatorDefault, digest, (CFIndex)digestLen);
    if (!digestCF) return 0;
    CFErrorRef error = NULL;
    CFDataRef sigCF = SecKeyCreateSignature(keyRef,
        kSecKeyAlgorithmECDSASignatureDigestX962SHA256, digestCF, &error);
    CFRelease(digestCF);
    if (error) CFRelease(error);
    if (!sigCF) return 0;
    CFIndex len = CFDataGetLength(sigCF);
    *sigOut = (uint8_t *)malloc((size_t)len);
    if (*sigOut) {
        CFDataGetBytes(sigCF, CFRangeMake(0, len), *sigOut);
        *sigLen = (size_t)len;
    } else {
        *sigLen = 0;
    }
    CFRelease(sigCF);
    return *sigOut ? 1 : 0;
}

// rampart_is_installed returns 1 if the cert is in Keychain, 0 otherwise.
static int rampart_is_installed(void) {
    const void *sKeys[] = { kSecClass,            kSecAttrLabel, kSecReturnRef,  kSecMatchLimit,    kSecUseDataProtectionKeychain };
    const void *sVals[] = { kSecClassCertificate, rampart_label, kCFBooleanTrue, kSecMatchLimitOne, kCFBooleanFalse };
    CFDictionaryRef sq = CFDictionaryCreate(kCFAllocatorDefault, sKeys, sVals, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef result = NULL;
    OSStatus st = SecItemCopyMatching(sq, &result);
    CFRelease(sq);
    if (st == errSecSuccess && result) { CFRelease(result); return 1; }
    return 0;
}

// rampart_has_gui_session returns 1 if this process has graphical session access.
static int rampart_has_gui_session(void) {
    SecuritySessionId sessionID;
    SessionAttributeBits attrs;
    if (SessionGetInfo(callerSecuritySession, &sessionID, &attrs) != errSessionSuccess) {
        return 0;
    }
    return (attrs & sessionHasGraphicAccess) ? 1 : 0;
}
*/
import "C"
import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"runtime"
	"unsafe"
)

// keychainSigner implements crypto.Signer backed by a Keychain SecKeyRef (TR29).
// Signing is delegated to SecKeyCreateSignature — the raw key never leaves Keychain.
type keychainSigner struct {
	pub    crypto.PublicKey // *ecdsa.PublicKey
	keyRef C.SecKeyRef
}

func (s *keychainSigner) Public() crypto.PublicKey { return s.pub }

func (s *keychainSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("empty digest")
	}
	var sigPtr *C.uint8_t
	var sigLen C.size_t
	ok := C.rampart_sign(s.keyRef,
		(*C.uint8_t)(unsafe.Pointer(&digest[0])),
		C.size_t(len(digest)),
		&sigPtr, &sigLen)
	if ok == 0 {
		return nil, fmt.Errorf("SecKeyCreateSignature failed")
	}
	defer C.free(unsafe.Pointer(sigPtr))
	return C.GoBytes(unsafe.Pointer(sigPtr), C.int(sigLen)), nil
}

func hasGUISession() bool {
	return C.rampart_has_gui_session() != 0
}

func cgoCertDER(certPEM []byte) ([]byte, error) {
	block, _ := decodePEM(certPEM)
	if block == nil {
		return nil, errors.New("invalid cert PEM")
	}
	return block, nil
}

// loadKeyRefFromKeychain returns the SecKeyRef from Keychain (may be nil).
func loadKeyRefFromKeychain() C.SecKeyRef {
	return C.rampart_load_key()
}

// releaseCFRef releases a CFTypeRef.
func releaseCFRef(ref C.SecKeyRef) {
	C.CFRelease(C.CFTypeRef(ref))
}

// setFinalizer registers CFRelease to run when the signer is GC'd.
func setSignerFinalizer(s *keychainSigner) {
	runtime.SetFinalizer(s, func(x *keychainSigner) {
		C.CFRelease(C.CFTypeRef(x.keyRef))
	})
}

func cgoSaveKey(x963 []byte) C.int {
	return C.int(C.rampart_save_key((*C.uint8_t)(unsafe.Pointer(&x963[0])), C.size_t(len(x963))))
}

func cgoSaveCert(der []byte) C.int {
	return C.int(C.rampart_save_cert((*C.uint8_t)(unsafe.Pointer(&der[0])), C.size_t(len(der))))
}

func cgoSetTrust() C.int {
	return C.int(C.rampart_set_trust())
}

func cgoRemoveKey() C.int {
	return C.int(C.rampart_remove_key())
}

func cgoRemoveCert() C.int {
	return C.int(C.rampart_remove_cert())
}

func cgoLoadCertDER() ([]byte, error) {
	var derPtr *C.uint8_t
	var derLen C.size_t
	st := C.int(C.rampart_load_cert_der(&derPtr, &derLen))
	if st == C.int(C.errSecItemNotFound) {
		return nil, nil // not found
	}
	if st != 0 {
		return nil, fmt.Errorf("Keychain cert lookup: OSStatus %d", st)
	}
	defer C.free(unsafe.Pointer(derPtr))
	return C.GoBytes(unsafe.Pointer(derPtr), C.int(derLen)), nil
}

func cgoIsInstalled() bool {
	return C.rampart_is_installed() != 0
}

func errSecDuplicate() C.int {
	return C.int(C.errSecDuplicateItem)
}

func errSecSuccess() C.int {
	return C.int(C.errSecSuccess)
}

func errSecItemNotFound() C.int {
	return C.int(C.errSecItemNotFound)
}

package enclave

// #cgo LDFLAGS: -framework CoreFoundation
// #cgo LDFLAGS: -framework Security
// #include <CoreFoundation/CoreFoundation.h>
// #include <Security/Security.h>
import "C"
import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"github.com/scottpass/cert-utils/crypto/ecies"
	"io"
	"unsafe"
)

var nilref C.CFTypeRef

type KeyAccess int

func (a KeyAccess) toProtection() (C.CFTypeRef, error) {
	if (a&PROTECTION_MASK)&((a*PROTECTION_MASK)-1) != 0 {
		return nilref, errors.New("invalid access level: multiple protection levels specified")
	}
	if (a & PROTECTION_MASK) == 0 {
		return nilref, errors.New("invalid access level: no protection level specified")
	}
	switch a & PROTECTION_MASK {
	case RequirePassword:
		return C.CFTypeRef(C.kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly), nil
	case RequireUnlock:
		return C.CFTypeRef(C.kSecAttrAccessibleWhenUnlockedThisDeviceOnly), nil
	case RequireFirstUnlock:
		return C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly), nil
	case AlwaysAccessible:
		return C.CFTypeRef(C.kSecAttrAccessibleAlwaysThisDeviceOnly), nil
	default:
		return nilref, errors.New("invalid access level: unknown protection level specified")
	}

}

func (a KeyAccess) toFlags() C.SecAccessControlCreateFlags {
	var ret C.SecAccessControlCreateFlags
	if a&RequireUserPresence != 0 {
		ret |= C.kSecAccessControlUserPresence
	}

	if a&RequireBiometry != 0 {
		ret |= C.kSecAccessControlBiometryAny
	}

	if a&RequireCurrentBiometry != 0 {
		ret |= C.kSecAccessControlBiometryCurrentSet
	}

	if a&RequireDevicePassword != 0 {
		ret |= C.kSecAccessControlDevicePasscode
	}

	if a&RequireWatch != 0 {
		ret |= C.kSecAccessControlWatch
	}

	if a&RequireOr != 0 {
		ret |= C.kSecAccessControlOr
	}

	if a&RequireAnd != 0 {
		ret |= C.kSecAccessControlAnd
	}

	return ret
}

const (
	RequirePassword KeyAccess = 1 << iota
	RequireUnlock
	RequireFirstUnlock
	AlwaysAccessible

	RequireUserPresence
	RequireBiometry
	RequireCurrentBiometry
	RequireDevicePassword
	RequireWatch
	RequireOr
	RequireAnd
	AllowOnlyPrivateKeyOps

	PROTECTION_MASK = RequirePassword | RequireUnlock | RequireFirstUnlock | AlwaysAccessible
)

type noCopy struct {
}

func (noCopy) Lock()   {}
func (noCopy) Unlock() {}

var ErrUnsupportedHash = errors.New("crypto: unsupported hash function")

// PrivateKey represents an ECDSA private key stored in the Secure Enclave.
// Any reference to a PrivateKey must be closed with Close() to avoid leaking memory.
type PrivateKey struct {
	noCopy
	key C.SecKeyRef
}

// Close releases the underlying reference to the private key.
func (k *PrivateKey) Close() error {
	if (unsafe.Pointer)(k.key) != nil {
		C.CFRelease(C.CFTypeRef(k.key))
		k.key = C.SecKeyRef(unsafe.Pointer(nil))
	}
	return nil
}

// Public returns a copy of the public portion of the key.
// The returned value is a *ecds.PublicKey instance.
func (k *PrivateKey) Public() crypto.PublicKey {
	var ar autorelease
	defer func() {
		_ = ar.Close()
	}()

	pubKeyRef := C.SecKeyCopyPublicKey(k.key)
	ar.Add(C.CFTypeRef(pubKeyRef))
	var errorRef C.CFErrorRef
	externalRep := C.SecKeyCopyExternalRepresentation(
		pubKeyRef,
		&errorRef,
	)
	ar.Add(C.CFTypeRef(externalRep))
	ar.Add(C.CFTypeRef(errorRef))

	if unsafe.Pointer(errorRef) != nil {
		panic(toGoError(errorRef))
	}

	return ecies.FromX963(toSlice(externalRep))
}

// Unwrap decrypts the provided ecies.WrapoedSercret using the private key.
func (k *PrivateKey) Unwrap(w *ecies.WrappedSecret) ([]byte, error) {
	pubKeyBytes := ecies.ToX963(w.EphemeralPublicKey)
	cipherText := make([]byte, len(pubKeyBytes)+len(w.Tag)+len(w.EncryptedData))
	copy(cipherText, pubKeyBytes)
	copy(cipherText[len(pubKeyBytes):], w.EncryptedData)
	copy(cipherText[len(pubKeyBytes)+len(w.EncryptedData):], w.Tag)

	var ar autorelease
	defer func() {
		_ = ar.Close()
	}()

	ctRef := C.CFDataCreate(C.kCFAllocatorDefault, (*C.uint8_t)(&cipherText[0]), C.CFIndex(len(cipherText)))
	ar.Add(C.CFTypeRef(ctRef))

	var errorRef C.CFErrorRef
	decryptedDataRef := C.SecKeyCreateDecryptedData(
		k.key,
		C.kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
		ctRef,
		&errorRef,
	)
	ar.Add(C.CFTypeRef(decryptedDataRef))
	ar.Add(C.CFTypeRef(errorRef))

	if unsafe.Pointer(errorRef) != nil {
		return nil, toGoError(errorRef)
	}

	ret := toSlice(decryptedDataRef)
	return ret, nil
}

func toSlice(dataRef C.CFDataRef) []byte {
	ret := make([]byte, C.CFDataGetLength(dataRef))
	C.CFDataGetBytes(dataRef, C.CFRangeMake(0, C.long(len(ret))), (*C.uint8_t)(&ret[0]))
	return ret
}

func toSecKeyRef(pubKey *ecdsa.PublicKey) (C.SecKeyRef, error) {
	var ar autorelease
	defer func() {
		_ = ar.Close()
	}()

	dataRef := ar.AddBytes(ecies.ToX963(pubKey))

	keyAttrsRef := ar.AddDict(map[C.CFStringRef]C.CFTypeRef{
		C.kSecAttrKeyType:  C.CFTypeRef(C.kSecAttrKeyTypeECSECPrimeRandom),
		C.kSecAttrKeyClass: C.CFTypeRef(C.kSecAttrKeyClassPublic),
	})

	var errorRef C.CFErrorRef
	keyRef := C.SecKeyCreateWithData(dataRef, C.CFDictionaryRef(unsafe.Pointer(keyAttrsRef)), &errorRef)
	ar.Add(C.CFTypeRef(errorRef))
	if unsafe.Pointer(errorRef) != nil {
		ar.Add(C.CFTypeRef(keyRef))
		return C.SecKeyRef(unsafe.Pointer(nil)), toGoError(errorRef)
	}
	return keyRef, nil
}

// Wrap encrypts data using the provided public key in a manner compatible with ecies.Wrap. This uses Apple's SecurityFramework
// implementation. This function is not strictly necessary, but is useful for testing bi-directional interop with the
// Secure Enclave.
func Wrap(pubKey *ecdsa.PublicKey, data []byte) (*ecies.WrappedSecret, error) {
	var ar autorelease
	defer func() {
		_ = ar.Close()
	}()
	keyRef, err := toSecKeyRef(pubKey)
	ar.Add(C.CFTypeRef(keyRef))
	if err != nil {
		return nil, err
	}

	ptRef := ar.AddBytes(data)

	var errorRef C.CFErrorRef
	ctRef := C.SecKeyCreateEncryptedData(keyRef, C.kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM, ptRef, &errorRef)
	ar.Add(C.CFTypeRef(ctRef))
	ar.Add(C.CFTypeRef(errorRef))
	if unsafe.Pointer(errorRef) != nil {
		return nil, toGoError(errorRef)
	}

	encryptedBytes := toSlice(ctRef)
	parsedKeyECDH := ecies.FromX963(encryptedBytes[:65])

	return &ecies.WrappedSecret{
		EncryptedData:      encryptedBytes[65 : len(encryptedBytes)-16],
		Tag:                encryptedBytes[len(encryptedBytes)-16:],
		EphemeralPublicKey: parsedKeyECDH,
	}, nil
}

// DeleteKey removes the private key with the provided tag from the Secure Enclave.
func DeleteKey(tag string) error {
	var ar autorelease
	defer func() {
		_ = ar.Close()
	}()

	dict := ar.AddDict(map[C.CFStringRef]C.CFTypeRef{
		C.kSecClass:        C.CFTypeRef(C.kSecClassKey),
		C.kSecAttrKeyClass: C.CFTypeRef(C.kSecAttrKeyClassPrivate),
		C.kSecAttrKeyType:  C.CFTypeRef(C.kSecAttrKeyTypeECSECPrimeRandom),
		C.kSecAttrLabel:    C.CFTypeRef(ar.AddString(tag)),
		C.kSecReturnRef:    C.CFTypeRef(C.kCFBooleanTrue),
	})

	status := C.SecItemDelete(C.CFDictionaryRef(unsafe.Pointer(dict)))
	if status != 0 {
		return AppleSecurityError{code: status}
	}
	return nil
}

// Sign signs the provided digest using the private key.
func (k *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, ErrUnsupportedHash
	}
	var ar autorelease
	defer func() {
		_ = ar.Close()
	}()

	digestDataRef := ar.AddBytes(digest)
	var errorRef C.CFErrorRef

	sigDataRef := C.SecKeyCreateSignature(
		k.key,
		C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
		digestDataRef,
		&errorRef,
	)
	ar.Add(C.CFTypeRef(sigDataRef))
	ar.Add(C.CFTypeRef(errorRef))

	if unsafe.Pointer(errorRef) != nil {
		return nil, toGoError(errorRef)
	}

	signature = make([]byte, C.CFDataGetLength(sigDataRef))
	C.CFDataGetBytes(sigDataRef, C.CFRangeMake(0, C.long(len(signature))), (*C.uint8_t)(&signature[0]))

	return signature, nil
}

// AppleSecurityError represents an error returned by Apple's SecurityFramework
type AppleSecurityError struct {
	code C.OSStatus
}

// Error returns a string representation of the error.
func (e AppleSecurityError) Error() string {
	var ar autorelease
	defer func() {
		_ = ar.Close()
	}()

	strRef := C.SecCopyErrorMessageString(e.code, nil)
	ar.Add(C.CFTypeRef(strRef))

	buf := make([]byte, C.CFStringGetLength(strRef)*4)
	C.CFStringGetCString(strRef, (*C.char)(unsafe.Pointer(&buf[0])), C.CFIndex(len(buf)), C.kCFStringEncodingUTF8)
	buf = buf[:C.strlen((*C.char)(unsafe.Pointer(&buf[0])))]
	return string(buf)
}

// LoadPrivateKey loads a handle to a private key from the secure enclave given it's tag.
func LoadPrivateKey(tag string) (*PrivateKey, error) {
	var ar autorelease
	defer func() {
		_ = ar.Close()
	}()

	dict := ar.AddDict(map[C.CFStringRef]C.CFTypeRef{
		C.kSecClass:        C.CFTypeRef(C.kSecClassKey),
		C.kSecAttrKeyClass: C.CFTypeRef(C.kSecAttrKeyClassPrivate),
		C.kSecAttrKeyType:  C.CFTypeRef(C.kSecAttrKeyTypeECSECPrimeRandom),
		C.kSecAttrLabel:    C.CFTypeRef(ar.AddString(tag)),
		C.kSecReturnRef:    C.CFTypeRef(C.kCFBooleanTrue),
	})

	var ret C.CFTypeRef
	status := C.SecItemCopyMatching(
		C.CFDictionaryRef(unsafe.Pointer(dict)),
		&ret,
	)

	if status != 0 {
		return nil, AppleSecurityError{code: status}
	}

	return &PrivateKey{key: C.SecKeyRef(ret)}, nil
}

// GeneratePrivateKey creates a new ECDSA P526 key in the secure enclave with the provided tag and access level.
func GeneratePrivateKey(tag string, accessGroup string, access KeyAccess) (*PrivateKey, error) {
	var ar autorelease
	defer func() {
		_ = ar.Close()
	}()

	prot, err := access.toProtection()
	if err != nil {
		return nil, err
	}

	var cferror C.CFErrorRef

	accessControlRef := C.SecAccessControlCreateWithFlags(
		C.kCFAllocatorDefault,
		prot,
		access.toFlags(),
		&cferror,
	)
	ar.Add(C.CFTypeRef(cferror))
	ar.Add(C.CFTypeRef(accessControlRef))

	if unsafe.Pointer(cferror) != nil {
		return nil, toGoError(cferror)
	}

	dict := ar.AddDict(map[C.CFStringRef]C.CFTypeRef{
		C.kSecAttrKeyType:        C.CFTypeRef(C.kSecAttrKeyTypeECSECPrimeRandom),
		C.kSecAttrLabel:          C.CFTypeRef(ar.AddString(tag)),
		C.kSecAttrKeySizeInBits:  C.CFTypeRef(ar.AddNumber(256)),
		C.kSecAttrTokenID:        C.CFTypeRef(C.kSecAttrTokenIDSecureEnclave),
		C.kSecAttrApplicationTag: C.CFTypeRef(ar.AddStringData(tag)),
		C.kSecPrivateKeyAttrs: C.CFTypeRef(unsafe.Pointer(ar.AddDict(map[C.CFStringRef]C.CFTypeRef{
			C.kSecAttrIsPermanent:   C.CFTypeRef(C.kCFBooleanTrue),
			C.kSecAttrAccessControl: C.CFTypeRef(accessControlRef),
			C.kSecAttrAccessGroup:   C.CFTypeRef(ar.AddString(accessGroup)),
		}))),
	})

	keyRef := C.SecKeyCreateRandomKey(C.CFDictionaryRef(unsafe.Pointer(dict)), &cferror)
	ar.Add(C.CFTypeRef(cferror))
	if unsafe.Pointer(cferror) != nil {
		return nil, toGoError(cferror)
	}
	return &PrivateKey{key: keyRef}, nil
}

func toGoError(cferror C.CFErrorRef) error {
	var ar autorelease
	defer func() {
		_ = ar.Close()
	}()

	strRef := C.CFErrorCopyDescription(cferror)
	ar.Add(C.CFTypeRef(strRef))

	buf := make([]byte, C.CFStringGetLength(strRef)*4)

	C.CFStringGetCString(strRef, (*C.char)(unsafe.Pointer(&buf[0])), C.long(len(buf)), C.kCFStringEncodingUTF8)
	buf = buf[:C.strlen((*C.char)(unsafe.Pointer(&buf[0])))]
	return errors.New(string(buf))
}

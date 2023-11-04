package ecies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

// WrappedSecret represents data encrypted using ecies, specifically with the
// kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM algorithm supported on apple platforms.
// See https://darthnull.org/secure-enclave-ecies/ for more info.
type WrappedSecret struct {
	//EncryptedData is the cypher text
	EncryptedData []byte
	//Tag is the AES GCM tag
	Tag []byte
	//EphermalPublicKey is the public key from the ephemeral keypair used to encrypt the data.
	EphemeralPublicKey *ecdsa.PublicKey
}

// Wrap encrypts data using the kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM algorithm supported on
// apple platforms. See https://darthnull.org/secure-enclave-ecies/ for more info.
// This algorithm:
//  1. Generates a random ephemeral ECDH keypair
//  2. Computes the shared secret between the ephemeral private key and the target public key using ECDH
//  3. Uses the ANSI X9.63 Key Derivation algorithm to derive a 32 byte key from the shared secret, using the X9.63 public key
//     format of the ephemeral public key as the shared info.
//  4. Uses the first 16 bytes of the derived key as the AES-GCM key, and the last 16 bytes as the AES-GCM IV (nonce)
//  5. Encrypts the data using AES-GCM.
//
// Note: Because the IV is derived from the ephemeral public key and the ecdh shared secret, we don't need to store it
// as one normally would when doing AES-GCM encryption.
//
// Only the P256 curve and SHA256 hash are supported.
func Wrap(data []byte, target *ecdsa.PublicKey) (*WrappedSecret, error) {
	ephemeralPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ephemeralPrivKeyECDH, err := ephemeralPrivKey.ECDH()
	if err != nil {
		return nil, err
	}
	targetECDH, err := target.ECDH()
	if err != nil {
		return nil, err
	}
	sharedSecret, err := ephemeralPrivKeyECDH.ECDH(targetECDH)

	pubKeyBytes := ToX963(ephemeralPrivKey.Public().(*ecdsa.PublicKey))

	derived := deriveKey(sharedSecret, pubKeyBytes)
	blockCipher, err := aes.NewCipher(derived[:16])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(blockCipher, 16)
	encryptedData := gcm.Seal(nil, derived[16:], data, nil)

	return &WrappedSecret{
		EncryptedData:      encryptedData[:len(data)],
		Tag:                encryptedData[len(data):],
		EphemeralPublicKey: ephemeralPrivKey.Public().(*ecdsa.PublicKey),
	}, nil
}

// Unwrap decrypts a WrappedSecret instance.
func Unwrap(w *WrappedSecret, privKey *ecdsa.PrivateKey) ([]byte, error) {
	privKeyECDH, err := privKey.ECDH()
	if err != nil {
		return nil, err
	}
	ephemeralPubKeyECDH, err := w.EphemeralPublicKey.ECDH()
	if err != nil {
		return nil, err
	}
	sharedSecret, err := privKeyECDH.ECDH(ephemeralPubKeyECDH)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ToX963(w.EphemeralPublicKey)

	derived := deriveKey(sharedSecret, pubKeyBytes)
	blockCipher, err := aes.NewCipher(derived[:16])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(blockCipher, 16)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, derived[16:], append(w.EncryptedData, w.Tag...), nil)
}

func deriveKey(dhSecret []byte, sharedInfo []byte) []byte {
	//We can remove the loop because the hash size and the output size are identical... so this just becomes
	//a sah256 sum of dhSecret + bigendian(1) + sharedInfo
	var hashInput = make([]byte, len(dhSecret)+len(sharedInfo)+4)
	copy(hashInput, dhSecret)
	binary.BigEndian.PutUint32(hashInput[len(dhSecret):], 1)
	copy(hashInput[len(dhSecret)+4:], sharedInfo)
	ret := sha256.Sum256(hashInput)
	return ret[:]
}

func FromX963(bytes []byte) *ecdsa.PublicKey {
	x := big.NewInt(0)
	y := big.NewInt(0)

	x.SetBytes(bytes[1:33])
	y.SetBytes(bytes[33:65])

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
}

func ToX963(pubKey *ecdsa.PublicKey) []byte {
	ret := make([]byte, 65)
	ret[0] = 4
	pubKey.X.FillBytes(ret[1:33])
	pubKey.Y.FillBytes(ret[33:65])
	return ret
}

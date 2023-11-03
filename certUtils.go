package cert_utils

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

var EncryptionTargetKeyExtensionOID = []int{1, 3, 9942, 1, 1}

func CertToPem(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

func PemToCert(s string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE block, got %s", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

func CertHash(cert *x509.Certificate) string {
	sha := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sha[:])
}

func PubKeyHash(key *ecdsa.PublicKey) (string, error) {
	//NOTE: This may look weird. We are converting the ecdsa key into an ECDH key,
	//then getting the hash of that key. Except MarshalPKIXPublicKey output ECDH keys as ECDSA keys.
	//However, go has a function to convert an ECDSA key to an ECDH key, but not the other way around
	//and we don't want to duplicate this method body. So, having this method call the ECDH method allows us
	//to reuse the code.
	ecdhKey, err := key.ECDH()
	if err != nil {
		return "", err
	}
	return PubKeyHashECDH(ecdhKey)
}

func PubKeyHashECDH(key *ecdh.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	sha := sha256.Sum256(der)
	return hex.EncodeToString(sha[:]), nil
}

func PubKeyFromPEM(s string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM data found")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("expected PUBLIC KEY block, got %s", block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		return nil, err
	}
	ret, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Not an ECDSA key")
	}
	return ret, nil
}

func PemFromPubKey(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})), nil
}

func GetEncryptionTargetKey(cert *x509.Certificate) (*ecdh.PublicKey, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(EncryptionTargetKeyExtensionOID) {
			pubAny, err := x509.ParsePKIXPublicKey(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("unable to parse key: %v", err)
			}
			ret, ok := pubAny.(*ecdsa.PublicKey)
			if !ok {
				return nil, errors.New("key is not an ECC key")
			}
			if ret.Curve != elliptic.P256() {
				return nil, errors.New("key does not use the P256 curve")
			}
			return ret, nil
		}
	}
	return nil, errors.New("no extension present")
}

func AddEncryptionTargetKey(cert *x509.Certificate, key *ecdh.PublicKey) error {
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}

	cert.ExtraExtensions = append(
		cert.ExtraExtensions,
		pkix.Extension{
			Id:       EncryptionTargetKeyExtensionOID,
			Critical: false,
			Value:    derBytes,
		},
	)
	return nil
}

func UniqueHashes(hashes ...string) bool {
	seen := make(map[string]bool)
	for _, hash := range hashes {
		if seen[hash] {
			return false
		}
		seen[hash] = true
	}
	return true
}

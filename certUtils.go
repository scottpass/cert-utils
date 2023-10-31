package cert_utils

import (
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

func GetEncryptionTargetKey(cert *x509.Certificate) (*ecdsa.PublicKey, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(EncryptionTargetKeyExtensionOID) {
			pubAny, err := x509.ParsePKIXPublicKey(ext.Value)
			if err != nil {
				return nil, err
			}
			ret, ok := pubAny.(*ecdsa.PublicKey)
			if !ok {
				return nil, errors.New("encryption target key is not an ECC key")
			}
			if ret.Curve != elliptic.P256() {
				return nil, errors.New("encryption target key does not use the P256 curve")
			}
			return ret, nil
		}
	}
	return nil, errors.New("cert is missing the encryption target key extension")
}

func AddEncryptionTargetKey(cert *x509.Certificate, key *ecdsa.PublicKey) error {
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

package cert_utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"path"
	"time"
)

var EncryptionTargetKeyExtensionOID = []int{1, 3, 9942, 1, 1}

// CertToPem converts a certificate to a PEM encoded string
func CertToPem(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

// PemToCert converts a PEM encoded string to a certificate
func PemToCert(s string) (*x509.Certificate, error) {
	if s == "" {
		return nil, nil
	}
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE block, got %s", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// CertHash returns the SHA256 hash of a certificate's DER encoding
func CertHash(cert *x509.Certificate) string {
	sha := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sha[:])
}

// PubKeyHash returns the SHA256 hash of a public key's DER encoding
func PubKeyHash(key *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	sha := sha256.Sum256(der)
	return hex.EncodeToString(sha[:]), nil
}

// PubKeyFromPEM converts a PEM encoded public key to an ECDSA public key
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

// PemFromPubKey converts an ECDSA public key to a PEM encoded string
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

// GetEncryptionTargetKey returns the key encoded in the Scott Pass EncryptionTargetKey extension attached to a cert
// or an error if no such extension is present.
func GetEncryptionTargetKey(cert *x509.Certificate) (*ecdsa.PublicKey, error) {
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

// AddEncryptionTargetKey adds a Scott Pass EncryptionTargetKey extension to a certificate template.
func AddEncryptionTargetKey(template *x509.Certificate, key *ecdsa.PublicKey) error {
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}

	template.ExtraExtensions = append(
		template.ExtraExtensions,
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

// GenerateSerial generates a random serial number for a certificate, using 126s bit of entropy.
func GenerateSerial() (*big.Int, error) {
	var bytes [16]byte
	_, err := rand.Read(bytes[:])
	if err != nil {
		return nil, err
	}

	bytes[0] &= 0x7f
	bytes[0] |= 0x40

	serial := big.NewInt(0)
	serial.SetBytes(bytes[:])
	return serial, nil
}

// CreateCACertTemplate creates a template for a CA certificate
func CreateCACertTemplate(accountID string, now time.Time) (*x509.Certificate, error) {
	serial, err := GenerateSerial()
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		BasicConstraintsValid:  true,
		ExcludedDNSDomains:     []string{"."},
		ExcludedEmailAddresses: []string{"."},
		ExcludedIPRanges: []*net.IPNet{
			{
				IP:   net.IPv4(0, 0, 0, 0),
				Mask: net.IPv4Mask(0, 0, 0, 0),
			},
		},
		PermittedURIDomains:         []string{accountID},
		PermittedDNSDomainsCritical: true,
		IsCA:                        true,
		KeyUsage:                    x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		NotBefore:                   now,
		NotAfter:                    now.Add(time.Hour * 24 * 30 * 18),
		SerialNumber:                serial,
		SignatureAlgorithm:          x509.ECDSAWithSHA256,
		Subject: pkix.Name{
			CommonName: accountID,
		},
	}

	return &template, nil
}

// CreateCACert creates a CA certificate
func CreateCACert(accountID string, pub *ecdsa.PublicKey, priv crypto.Signer, now time.Time) (*x509.Certificate, error) {
	template, err := CreateCACertTemplate(accountID, now)
	if err != nil {
		return nil, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certBytes)
}

// CreateDeviceCertTemplate creates a template for a device certificate
func CreateDeviceCertTemplate(
	caCert *x509.Certificate,
	accountID string,
	deviceName string,
	baseUrl *url.URL,
	pubEncryption *ecdsa.PublicKey,
	now time.Time,
) (*x509.Certificate, error) {
	serial, err := GenerateSerial()
	if err != nil {
		return nil, err
	}

	ocspUrl := *baseUrl
	ocspUrl.Path = path.Join(ocspUrl.Path, "v1", "ocsp")
	issuerUrl := *baseUrl
	issuerUrl.Path = path.Join(issuerUrl.Path, "v1", "accounts", url.PathEscape(accountID), "cas", CertHash(caCert))
	spUriSan, err := url.Parse(fmt.Sprintf("sp://%v/%v", url.PathEscape(accountID), url.PathEscape(deviceName)))
	if err != nil {
		return nil, err
	}

	ret := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  false,
		IssuingCertificateURL: []string{
			issuerUrl.String(),
		},
		KeyUsage:  x509.KeyUsageDigitalSignature,
		NotBefore: now,
		NotAfter:  now.Add(time.Hour * 24 * 30 * 3),
		OCSPServer: []string{
			ocspUrl.String(),
		},
		SerialNumber:       serial,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		URIs: []*url.URL{
			spUriSan,
		},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}

	err = AddEncryptionTargetKey(ret, pubEncryption)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// CreateDeviceCert creates a device certificate
func CreateDeviceCert(
	caCert *x509.Certificate,
	caSigner crypto.Signer,
	accountID string,
	deviceName string,
	baseUrl *url.URL,
	pub *ecdsa.PublicKey,
	pubEncryption *ecdsa.PublicKey,
	now time.Time,
) (*x509.Certificate, error) {

	template, err := CreateDeviceCertTemplate(caCert, accountID, deviceName, baseUrl, pubEncryption, now)
	if err != nil {
		return nil, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caSigner)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(cert)
}

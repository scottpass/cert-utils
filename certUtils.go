package cert_utils

import (
	"crypto"
	"crypto/ecdh"
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
			return ret.ECDH()
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

// GenerateSerial generates a random serial number for a certificate, using 126s bit of entropy.
// 16 bytes are generated and interpreted as a big-endian integer. The left most bit is awlays set to 0, and the second
// left most bit is always set to 1. This ensures the number is not negative and that the leading octet is not 0. The
// X509 spec requires that the serial not be negative and that if the lading octet is 0 that it be truncated.  By
// fixing the first 2 bits, we maintain 126 bits of entropy.
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

type CACertParams struct {
	AccountID string
	CAPub     *ecdsa.PublicKey
	CASigner  crypto.Signer
	Now       time.Time
}

func CreateCACertTemplate(p *CACertParams) (*x509.Certificate, error) {
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
		PermittedURIDomains:         []string{p.AccountID},
		PermittedDNSDomainsCritical: true,
		IsCA:                        true,
		KeyUsage:                    x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		NotBefore:                   p.Now,
		NotAfter:                    p.Now.Add(time.Hour * 24 * 30 * 18),
		SerialNumber:                serial,
		SignatureAlgorithm:          x509.ECDSAWithSHA256,
		Subject: pkix.Name{
			CommonName: p.AccountID,
		},
	}

	return &template, nil
}

func CreateCACert(p *CACertParams) (*x509.Certificate, error) {
	template, err := CreateCACertTemplate(p)
	if err != nil {
		return nil, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, p.CAPub, p.CASigner)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certBytes)
}

type DeviceCertParams struct {
	CACert        *x509.Certificate
	CASigner      crypto.Signer
	AccountID     string
	DeviceName    string
	BaseUrl       *url.URL
	DevicePub     *ecdsa.PublicKey
	EncryptionPub *ecdh.PublicKey
	Now           time.Time
}

func CreateDeviceCertTemplate(p *DeviceCertParams) (*x509.Certificate, error) {
	serial, err := GenerateSerial()
	if err != nil {
		return nil, err
	}

	ocspUrl := *p.BaseUrl
	ocspUrl.Path = path.Join(ocspUrl.Path, "v1", "ocsp")
	issuerUrl := *p.BaseUrl
	issuerUrl.Path = path.Join(issuerUrl.Path, "v1", "accounts", url.PathEscape(p.AccountID), "cas", CertHash(p.CACert))
	spUriSan, err := url.Parse(fmt.Sprintf("sp://%v/%v", url.PathEscape(p.AccountID), url.PathEscape(p.DeviceName)))
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
		NotBefore: p.Now,
		NotAfter:  p.Now.Add(time.Hour * 24 * 30 * 3),
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

	err = AddEncryptionTargetKey(ret, p.EncryptionPub)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func CreateDeviceCert(p *DeviceCertParams) (*x509.Certificate, error) {
	template, err := CreateDeviceCertTemplate(p)
	if err != nil {
		return nil, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, p.CACert, p.DevicePub, p.CASigner)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(cert)
}

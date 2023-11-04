//go:build darwin

package enclave_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"github.com/google/uuid"
	"github.com/scottpass/cert-utils/crypto/ecies"
	"github.com/scottpass/cert-utils/crypto/enclave"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSign(t *testing.T) {
	uuid, err := uuid.NewRandom()
	require.NoError(t, err)

	privKey, err := enclave.GeneratePrivateKey(uuid.String(), "AX8VV6MP9Q.com.scottpass.test.enclave", enclave.RequireFirstUnlock|enclave.AllowOnlyPrivateKeyOps)
	require.NoError(t, err)

	defer privKey.Close()
	defer enclave.DeleteKey(uuid.String())

	digest := sha256.Sum256([]byte("Iran"))
	sig, err := privKey.Sign(rand.Reader, digest[:], crypto.SHA256)

	require.NoError(t, err)
	pubKey := privKey.Public().(*ecdsa.PublicKey)

	require.True(t, ecdsa.VerifyASN1(pubKey, digest[:], sig))
}

func TestLoadPrivateKey(t *testing.T) {
	uuid, err := uuid.NewRandom()
	require.NoError(t, err)

	privKey, err := enclave.GeneratePrivateKey(uuid.String(), "AX8VV6MP9Q.com.scottpass.test.enclave", enclave.RequireFirstUnlock|enclave.AllowOnlyPrivateKeyOps)
	require.NoError(t, err)
	defer func() {
		if privKey != nil {
			_ = privKey.Close()
		}
	}()
	defer enclave.DeleteKey(uuid.String())

	pubKey := privKey.Public().(*ecdsa.PublicKey)
	_ = privKey.Close()
	privKey = nil

	privKey, err = enclave.LoadPrivateKey(uuid.String())
	require.NoError(t, err)
	pubKey2 := privKey.Public().(*ecdsa.PublicKey)
	require.Equal(t, pubKey, pubKey2)
}

func TestLoadPrivateKeyDNE(t *testing.T) {
	_, err := enclave.LoadPrivateKey("DNE")
	require.Error(t, err)
	require.Equal(t, "The specified item could not be found in the keychain.", err.Error())
}

func TestDeleteKey(t *testing.T) {
	uuid, err := uuid.NewRandom()
	require.NoError(t, err)

	privKey, err := enclave.GeneratePrivateKey(uuid.String(), "AX8VV6MP9Q.com.scottpass.test.enclave", enclave.RequireFirstUnlock|enclave.AllowOnlyPrivateKeyOps)
	require.NoError(t, err)
	privKey.Close()

	err = enclave.DeleteKey(uuid.String())
	require.NoError(t, err)
	_, err = enclave.LoadPrivateKey(uuid.String())
	require.Error(t, err)
	require.Equal(t, "The specified item could not be found in the keychain.", err.Error())
}

func TestDeleteKeyDNE(t *testing.T) {
	err := enclave.DeleteKey("DNE")
	require.Error(t, err)
	require.Equal(t, "The specified item could not be found in the keychain.", err.Error())
}

func TestWrapUnwrap(t *testing.T) {
	uuid, err := uuid.NewRandom()
	require.NoError(t, err)

	privKey, err := enclave.GeneratePrivateKey(uuid.String(), "AX8VV6MP9Q.com.scottpass.test.enclave", enclave.RequireFirstUnlock|enclave.AllowOnlyPrivateKeyOps)
	require.NoError(t, err)
	defer privKey.Close()
	defer enclave.DeleteKey(uuid.String())

	wrapped, err := ecies.Wrap([]byte("Hello World"), privKey.Public().(*ecdsa.PublicKey))
	require.NoError(t, err)

	unwrapped, err := privKey.Unwrap(wrapped)
	require.NoError(t, err)
	require.Equal(t, "Hello World", string(unwrapped))
}

func TestWrapUnwrap2(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ws, err := enclave.Wrap(privKey.Public().(*ecdsa.PublicKey), []byte("Hell World"))
	require.NoError(t, err)
	pt, err := ecies.Unwrap(ws, privKey)
	require.NoError(t, err)
	require.Equal(t, "Hell World", string(pt))
}

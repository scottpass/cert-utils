package ecies_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/scottpass/cert-utils/crypto/ecies"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	privKeyReceiver, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	w, err := ecies.Wrap([]byte("hello"), privKeyReceiver.Public().(*ecdsa.PublicKey))
	require.NoError(t, err)
	data, err := ecies.Unwrap(w, privKeyReceiver)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}

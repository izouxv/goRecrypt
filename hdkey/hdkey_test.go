package hdkey

import (
	"crypto/elliptic"
	"encoding/hex"
	"testing"

	"github.com/izouxv/goRecrypt/pre"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: The official BIP32 test vectors are designed for the secp256k1 curve.
// Since we are using standard library curves (like P-256), these tests will verify the self-consistency of the code logic.

func TestNewMaster(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	curve := elliptic.P256()

	masterKey, err := NewMaster(seed, curve)
	require.NoError(t, err)
	require.NotNil(t, masterKey)

	assert.Equal(t, byte(0), masterKey.Depth)
	assert.Equal(t, uint32(0), masterKey.Index)
	assert.Equal(t, []byte{0, 0, 0, 0}, masterKey.ParentFP)
	assert.NotNil(t, masterKey.PrivateKey)
	assert.NotNil(t, masterKey.PublicKey)
	assert.Len(t, masterKey.ChainCode, 32)

	// Test invalid seed lengths
	_, err = NewMaster([]byte{1, 2, 3}, curve)
	assert.ErrorIs(t, err, ErrInvalidSeedLen)

	_, err = NewMaster(make([]byte, 65), curve)
	assert.ErrorIs(t, err, ErrInvalidSeedLen)
}

func TestDerivation(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	curve := elliptic.P256()
	masterKey, err := NewMaster(seed, curve)
	require.NoError(t, err)

	// Test hardened derivation: m/0'
	childHardened, err := masterKey.Derive(HardenedKeyStart + 0)
	require.NoError(t, err)
	assert.Equal(t, byte(1), childHardened.Depth)
	assert.Equal(t, HardenedKeyStart+0, childHardened.Index)
	assert.Equal(t, masterKey.Fingerprint(), childHardened.ParentFP)
	assert.NotNil(t, childHardened.PrivateKey)
	assert.NotEqual(t, masterKey.PrivateKey.D, childHardened.PrivateKey.D)

	// Test normal derivation: m/0
	childNormal, err := masterKey.Derive(0)
	require.NoError(t, err)
	assert.Equal(t, byte(1), childNormal.Depth)
	assert.Equal(t, uint32(0), childNormal.Index)
	assert.Equal(t, masterKey.Fingerprint(), childNormal.ParentFP)
	assert.NotNil(t, childNormal.PrivateKey)
	assert.NotEqual(t, masterKey.PrivateKey.D, childNormal.PrivateKey.D)

	// Verify that hardened and normal derivation produce different keys
	assert.NotEqual(t, childHardened.PrivateKey.D, childNormal.PrivateKey.D)
}

func TestDerivePath(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	curve := elliptic.P256()
	masterKey, err := NewMaster(seed, curve)
	require.NoError(t, err)

	path := "m/44'/0'/0'/0/0"
	derivedKey, err := masterKey.DerivePath(path)
	require.NoError(t, err)
	require.NotNil(t, derivedKey)

	assert.Equal(t, byte(5), derivedKey.Depth)
	assert.Equal(t, uint32(0), derivedKey.Index)

	// Derive step-by-step and compare
	k1, _ := masterKey.Derive(44 + HardenedKeyStart)
	k2, _ := k1.Derive(0 + HardenedKeyStart)
	k3, _ := k2.Derive(0 + HardenedKeyStart)
	k4, _ := k3.Derive(0)
	k5, _ := k4.Derive(0)

	assert.Equal(t, k5.PrivateKey.D, derivedKey.PrivateKey.D)
	assert.Equal(t, k5.PublicKey.X, derivedKey.PublicKey.X)
	assert.Equal(t, k5.ChainCode, derivedKey.ChainCode)

	// Test invalid path
	_, err = masterKey.DerivePath("m/a/b/c")
	assert.Error(t, err)
}

func TestPublicDerivation(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	curve := elliptic.P256()
	masterKey, err := NewMaster(seed, curve)
	require.NoError(t, err)

	// Create a public-only key: m/1
	parentKey, err := masterKey.Derive(1)
	require.NoError(t, err)
	parentPubKey, err := parentKey.Neuter()
	require.NoError(t, err)
	assert.Nil(t, parentPubKey.PrivateKey)

	// Derive a normal child key from the public key: m/1/2
	childFromPublic, err := parentPubKey.Derive(2)
	require.NoError(t, err)
	assert.Nil(t, childFromPublic.PrivateKey)

	// Derive the same child key from the private key for comparison
	childFromPrivate, err := parentKey.Derive(2)
	require.NoError(t, err)

	// The public keys should match
	assert.Equal(t, childFromPrivate.PublicKey.X, childFromPublic.PublicKey.X)
	assert.Equal(t, childFromPrivate.PublicKey.Y, childFromPublic.PublicKey.Y)
	assert.Equal(t, childFromPrivate.ChainCode, childFromPublic.ChainCode)

	// Attempt to derive a hardened child key from a public key (should fail)
	_, err = parentPubKey.Derive(HardenedKeyStart)
	assert.ErrorIs(t, err, ErrCannotDeriveHardenedFromPublic)
}

func TestKeyEncryptionDecryption(t *testing.T) {
	// 1. Setup: Create a master key
	seed, _ := hex.DecodeString("101112131415161718191a1b1c1d1e1f") // Use a different seed to avoid conflicts with other tests
	curve := elliptic.P256()
	masterKey, err := NewMaster(seed, curve)
	require.NoError(t, err)
	require.NotNil(t, masterKey)

	// 2. Define a message
	message := []byte("This is a test message for encryption and decryption using an HD key.")

	// 3. Test with the master key
	// Encrypt with the master public key
	cipherTextMaster, capsuleMaster, err := pre.Encrypt(message, masterKey.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, cipherTextMaster)
	require.NotNil(t, capsuleMaster)

	// Decrypt with the master private key
	plainTextMaster, err := pre.DecryptOnMyPriKey(masterKey.PrivateKey, capsuleMaster, cipherTextMaster)
	require.NoError(t, err)
	assert.Equal(t, message, plainTextMaster)

	// 4. Test with a child key
	// Derive a child key
	childKey, err := masterKey.DerivePath("m/1'/2/3'")
	require.NoError(t, err)
	require.NotNil(t, childKey)

	// Encrypt with the child public key
	cipherTextChild, capsuleChild, err := pre.Encrypt(message, childKey.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, cipherTextChild)
	require.NotNil(t, capsuleChild)

	// Decrypt with the child private key
	plainTextChild, err := pre.DecryptOnMyPriKey(childKey.PrivateKey, capsuleChild, cipherTextChild)
	require.NoError(t, err)
	assert.Equal(t, message, plainTextChild)
}

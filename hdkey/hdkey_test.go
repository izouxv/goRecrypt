package hdkey

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/izouxv/goRecrypt/curve"
	"github.com/izouxv/goRecrypt/pre"
	"github.com/izouxv/goRecrypt/utils"
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

func TestKey_GenerateThresholdReKey(t *testing.T) {
	// 1. Setup: Create Alice's master key and Bob's key
	seed, _ := hex.DecodeString("202122232425262728292a2b2c2d2e2f")
	curve := elliptic.P256()
	aliceKey, err := NewMaster(seed, curve)
	require.NoError(t, err)

	bobPrivKey, bobPubKey, err := utils.GenerateKeys(curve)
	require.NoError(t, err)

	// 2. Use the method on alice's key to generate shares
	n, threshold := 5, 3
	shares, pubX, err := aliceKey.GenerateThresholdReKey(bobPubKey, n, threshold)
	require.NoError(t, err)
	require.Len(t, shares, n)
	require.NotNil(t, pubX)

	// 3. Encrypt a message with Alice's public key
	message := []byte("test message for hdkey threshold re-key generation")
	cipherText, originalCapsule, err := pre.Encrypt(message, aliceKey.PublicKey)
	require.NoError(t, err)

	// 4. Simulate re-encryption and combination
	partialCapsules := make([]*pre.PartialCapsule, 0, threshold)
	for i := 0; i < threshold; i++ {
		pCap, err := pre.PartialReEncryption(shares[i], originalCapsule)
		require.NoError(t, err)
		partialCapsules = append(partialCapsules, pCap)
	}

	finalCapsule, err := pre.CombineCapsules(partialCapsules, curve)
	require.NoError(t, err)

	// 5. Bob decrypts
	plainText, err := pre.Decrypt(bobPrivKey, finalCapsule, pubX, cipherText)
	require.NoError(t, err)
	assert.Equal(t, message, plainText)
}

func TestEthereumIntegration(t *testing.T) {
	// 1. Setup: Use secp256k1 curve and a test seed
	curve := curve.CurveGet("secp256k1")
	require.NotNil(t, curve, "secp256k1 curve should be registered")

	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	masterKey, err := NewMaster(seed, curve)
	require.NoError(t, err)

	// 2. Derive the standard Ethereum account key (BIP44)
	path := "m/44'/60'/0'/0/0"
	accountKey, err := masterKey.DerivePath(path)
	require.NoError(t, err)
	require.NotNil(t, accountKey)

	// 3. Generate the Ethereum address from the derived public key
	address, err := accountKey.Address()
	require.NoError(t, err)
	t.Logf("Derived Ethereum Address: 0x%s", hex.EncodeToString(address))
	// A real address would be checked against a known value if the seed was standard.
	// For this test, we just ensure it's 20 bytes long.
	require.Len(t, address, 20)

	// 4. Create a dummy transaction hash to be signed
	txData := []byte("this is a dummy transaction to be signed")
	txHash := sha256.Sum256(txData)

	// 5. Sign the transaction hash with the derived private key
	signature, err := accountKey.Sign(txHash[:])
	require.NoError(t, err)
	require.NotEmpty(t, signature)
	t.Logf("Signature (ASN.1 DER): %s", hex.EncodeToString(signature))

	// 6. Verify the signature with the derived public key
	// Verification should succeed with the correct key and hash
	valid := accountKey.Verify(txHash[:], signature)
	assert.True(t, valid, "Signature should be valid with the correct key")

	// 7. Negative tests for verification
	// Verification should fail with a different hash
	wrongTxData := []byte("this is a different transaction")
	wrongTxHash := sha256.Sum256(wrongTxData)
	invalid := accountKey.Verify(wrongTxHash[:], signature)
	assert.False(t, invalid, "Signature should be invalid with a different hash")

	// Verification should fail with a different public key (e.g., the master key)
	invalid = masterKey.Verify(txHash[:], signature)
	assert.False(t, invalid, "Signature should be invalid with a different public key")
}

package keystore

import (
	"crypto/elliptic"
	"testing"

	"github.com/izouxv/goRecrypt/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptKey(t *testing.T) {
	// Use a lower N for faster testing
	originalScryptN := ScryptN
	ScryptN = 2
	defer func() { ScryptN = originalScryptN }()

	// 1. Generate a key
	curve := elliptic.P256()
	key, _, err := utils.GenerateKeys(curve)
	require.NoError(t, err)

	password := "my-secret-password"

	// 2. Encrypt the key
	keystoreBytes, err := EncryptKey(key, password)
	require.NoError(t, err)
	require.NotEmpty(t, keystoreBytes)

	t.Logf("Keystore JSON: %s", string(keystoreBytes))

	// 3. Decrypt with the correct password
	decryptedKey, err := DecryptKey(keystoreBytes, password)
	require.NoError(t, err)
	require.NotNil(t, decryptedKey)

	// 4. Verify the keys are identical
	assert.True(t, key.Equal(decryptedKey), "Decrypted key should be identical to the original")

	// 5. Attempt to decrypt with the wrong password
	_, err = DecryptKey(keystoreBytes, "wrong-password")
	assert.ErrorIs(t, err, ErrInvalidPassword)
}

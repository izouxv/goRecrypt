package shamir

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitAndCombine(t *testing.T) {
	// Use P-256 curve's order as the prime field
	prime := elliptic.P256().Params().N

	// Generate a random secret
	secret, err := rand.Int(rand.Reader, prime)
	require.NoError(t, err)

	t.Run("2-of-3 scheme", func(t *testing.T) {
		n, threshold := 3, 2
		shares, err := Split(secret, n, threshold, prime)
		require.NoError(t, err)
		require.Len(t, shares, n)

		// Combine with exactly `threshold` shares
		sharesToCombine := []*Share{shares[0], shares[2]}
		combinedSecret, err := Combine(sharesToCombine, prime)
		require.NoError(t, err)
		assert.Equal(t, 0, secret.Cmp(combinedSecret), "Combined secret should match original")

		// Combine with more than `threshold` shares (all 3)
		combinedSecretAll, err := Combine(shares, prime)
		require.NoError(t, err)
		assert.Equal(t, 0, secret.Cmp(combinedSecretAll), "Combined secret with all shares should match original")

		// Combine with fewer than `threshold` shares (should not match)
		sharesNotEnough := []*Share{shares[1]}
		combinedSecretWrong, err := Combine(sharesNotEnough, prime)
		require.NoError(t, err)
		assert.NotEqual(t, 0, secret.Cmp(combinedSecretWrong), "Combined secret with insufficient shares should not match original")
	})
}

func TestSplitInvalidParameters(t *testing.T) {
	prime := elliptic.P256().Params().N
	secret := big.NewInt(12345)

	// Test t <= 1
	_, err := Split(secret, 3, 1, prime)
	assert.Error(t, err, "Should return error for t <= 1")

	// Test n < t
	_, err = Split(secret, 2, 3, prime)
	assert.Error(t, err, "Should return error for n < t")
}

func TestCombineEmptyShares(t *testing.T) {
	prime := elliptic.P256().Params().N
	_, err := Combine([]*Share{}, prime)
	assert.Error(t, err, "Should return error for empty shares slice")
}

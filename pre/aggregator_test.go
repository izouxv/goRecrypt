package pre

import (
	"crypto/elliptic"
	"testing"

	"github.com/izouxv/goRecrypt/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThresholdAggregator(t *testing.T) {
	// 1. Setup
	curve := elliptic.P256()
	aPriKey, aPubKey, _ := utils.GenerateKeys(curve)
	_, bPubKey, _ := utils.GenerateKeys(curve)

	n, threshold := 5, 3
	rkShares, _, err := ThresholdReKeyGen(aPriKey, bPubKey, n, threshold)
	require.NoError(t, err)

	_, originalCapsule, err := Encrypt([]byte("test"), aPubKey)
	require.NoError(t, err)

	// 2. Create Aggregator
	aggregator, err := NewThresholdAggregator(threshold)
	require.NoError(t, err)

	// 3. Add shares one by one
	// Add first share
	pCap1, _ := PartialReEncryption(rkShares[0], originalCapsule)
	finalCapsule, err := aggregator.AddPartialCapsule(pCap1)
	require.NoError(t, err)
	assert.Nil(t, finalCapsule, "Should not have a final capsule after 1 share")

	// Add second share
	pCap2, _ := PartialReEncryption(rkShares[1], originalCapsule)
	finalCapsule, err = aggregator.AddPartialCapsule(pCap2)
	require.NoError(t, err)
	assert.Nil(t, finalCapsule, "Should not have a final capsule after 2 shares")

	// Add a duplicate share (should fail)
	_, err = aggregator.AddPartialCapsule(pCap1)
	assert.Error(t, err, "Should return error for duplicate share")

	// Add third share (threshold met)
	pCap3, _ := PartialReEncryption(rkShares[2], originalCapsule)
	finalCapsule, err = aggregator.AddPartialCapsule(pCap3)
	require.NoError(t, err)
	assert.NotNil(t, finalCapsule, "Should have a final capsule after 3 shares")

	// Verify the internal map is cleared
	aggregator.mu.Lock()
	assert.Empty(t, aggregator.collected, "Internal map should be cleared after successful combination")
	aggregator.mu.Unlock()
}

func TestNewThresholdAggregator_InvalidThreshold(t *testing.T) {
	_, err := NewThresholdAggregator(1)
	assert.Error(t, err, "Should fail for threshold <= 1")

	_, err = NewThresholdAggregator(0)
	assert.Error(t, err, "Should fail for threshold <= 1")
}

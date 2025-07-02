package pre

import (
	"crypto/elliptic"
	"fmt"
	"github.com/izouxv/goRecrypt/curve"
	"math/big"
	"testing"

	"github.com/izouxv/goRecrypt/shamir"
	"github.com/izouxv/goRecrypt/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThresholdProxyReEncryption(t *testing.T) {
	curves := []elliptic.Curve{elliptic.P256(), elliptic.P384(), curve.CurveGet("secp256k1")} // P521 is too slow for this test

	for _, CURVE := range curves {
		t.Run(fmt.Sprintf("Curve_%s", CURVE.Params().Name), func(t *testing.T) {
			// 1. Setup: Alice and Bob generate key pairs
			aPriKey, aPubKey, err := utils.GenerateKeys(CURVE)
			require.NoError(t, err)
			bPriKey, bPubKey, err := utils.GenerateKeys(CURVE)
			require.NoError(t, err)

			// 2. Alice encrypts a message for herself
			message := []byte("This is a secret message for threshold PRE.")
			cipherText, originalCapsule, err := Encrypt(message, aPubKey)
			require.NoError(t, err)

			// 3. Alice generates threshold re-key shares for the proxies
			// We'll use a 2-of-3 threshold scheme
			n := 3
			threshold := 2
			rkShares, pubX, err := ThresholdReKeyGen(aPriKey, bPubKey, n, threshold)
			require.NoError(t, err)
			require.Len(t, rkShares, n)

			// --- Simulate network transmission of shares ---
			rkSharesBytes := make([][]byte, n)
			for i, share := range rkShares {
				rkSharesBytes[i], err = MarshalReKeyShare(share)
				require.NoError(t, err)
			}
			// Proxies unmarshal their shares
			unmarshaledShares := make([]*ReKeyShare, n)
			for i, sBytes := range rkSharesBytes {
				unmarshaledShares[i], err = UnmarshalReKeyShare(sBytes)
				require.NoError(t, err)
			}
			// --- End simulation ---

			// 4. Proxies perform partial re-encryption
			// We'll use `threshold` number of proxies (e.g., proxy 0 and proxy 2)
			partialCapsules := make([]*PartialCapsule, 0, threshold)

			// Let's pick shares 0 and 2
			indicesToUse := []int{0, 2}

			for _, i := range indicesToUse {
				pCap, err := PartialReEncryption(unmarshaledShares[i], originalCapsule)
				require.NoError(t, err)
				partialCapsules = append(partialCapsules, pCap)
			}

			// --- Simulate network transmission of partial capsules ---
			pCapsBytes := make([][]byte, len(partialCapsules))
			for i, pCap := range partialCapsules {
				pCapsBytes[i], err = pCap.Encode()
				require.NoError(t, err)
			}
			// Bob unmarshals the partial capsules
			unmarshaledPCaps := make([]*PartialCapsule, len(pCapsBytes))
			for i, pBytes := range pCapsBytes {
				pCap := &PartialCapsule{}
				err = pCap.Decode(pBytes)
				require.NoError(t, err)
				unmarshaledPCaps[i] = pCap
			}
			// --- End simulation ---

			// 5. An aggregator or Bob combines the partial capsules
			finalCapsule, err := CombineCapsules(unmarshaledPCaps, CURVE)
			require.NoError(t, err)

			// 6. Bob decrypts the message with the final combined capsule
			plainText, err := Decrypt(bPriKey, finalCapsule, pubX, cipherText)
			require.NoError(t, err)

			// 7. Verify the decrypted message is correct
			assert.Equal(t, message, plainText)

			// --- Sanity Check: Compare with non-threshold version ---
			// This check ensures that the final derived AES key is the same as what would be
			// derived in a non-threshold scheme with the same underlying ephemeral keys.
			// We need to reconstruct the original `rk` to do this.
			rkSharesToCombine := make([]*shamir.Share, 0, threshold)
			for _, i := range indicesToUse {
				rkSharesToCombine = append(rkSharesToCombine, rkShares[i])
			}
			reconstructedRK, err := shamir.Combine(rkSharesToCombine, CURVE.Params().N)
			require.NoError(t, err)

			nonThresholdCapsule, err := ReEncryption(reconstructedRK, originalCapsule)
			require.NoError(t, err)
			assert.True(t, finalCapsule.Equal(nonThresholdCapsule))
		})
	}
}

func TestThresholdSerialization(t *testing.T) {
	CURVE := elliptic.P256()

	// 1. Test ReKeyShare serialization
	share := &ReKeyShare{
		X: big.NewInt(1234567890),
		Y: big.NewInt(9876543210),
	}
	shareBytes, err := MarshalReKeyShare(share)
	require.NoError(t, err)
	require.NotEmpty(t, shareBytes)

	unmarshaledShare, err := UnmarshalReKeyShare(shareBytes)
	require.NoError(t, err)
	assert.Equal(t, share.X, unmarshaledShare.X)
	assert.Equal(t, share.Y, unmarshaledShare.Y)

	// 2. Test PartialCapsule serialization
	_, pubE, _ := utils.GenerateKeys(CURVE)
	_, pubV, _ := utils.GenerateKeys(CURVE)
	pCap := &PartialCapsule{
		E: pubE,
		V: pubV,
		S: big.NewInt(111222333),
		X: big.NewInt(444555666),
	}

	pCapBytes, err := pCap.Encode()
	require.NoError(t, err)
	decodedPCap := &PartialCapsule{}
	err = decodedPCap.Decode(pCapBytes)
	require.NoError(t, err)
	assert.Equal(t, pCap.S, decodedPCap.S)
	assert.Equal(t, pCap.X, decodedPCap.X)
	assert.True(t, pCap.E.Equal(decodedPCap.E))
	assert.True(t, pCap.V.Equal(decodedPCap.V))
}

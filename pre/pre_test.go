package pre

import (
	"crypto/elliptic"
	"fmt"
	"testing"

	"github.com/izouxv/goRecrypt/curve"
	"github.com/izouxv/goRecrypt/utils"
	"github.com/stretchr/testify/assert"
)

func Test_ProxyReEncryption(t *testing.T) {
	curves := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521(), curve.CurveGet("secp256k1")}

	for _, CURVE := range curves {
		t.Run(fmt.Sprintf("Curve_%s", CURVE.Params().Name), func(t *testing.T) {
			// Alice Generate Alice key-pair
			aPriKey, aPubKey, _ := utils.GenerateKeys(CURVE)
			// Bob Generate Bob key-pair
			bPriKey, bPubKey, _ := utils.GenerateKeys(CURVE)

			//alice gen key
			capsule, keyBytes, err := EncryptKeyGen(aPubKey)
			assert.Nil(t, err)
			keyBytes2, err := RecreateAesKeyByMyPriKey(capsule, aPriKey)
			assert.Nil(t, err)
			assert.Equal(t, keyBytes, keyBytes2)

			//alice gen pubX to bob
			rk, pubX, err := ReKeyGen(aPriKey, bPubKey)
			assert.Nil(t, err)
			// fmt.Println("rk:", rk)

			// Server executes re-encrypt
			newCapsule, err := ReEncryption(rk, capsule)
			assert.Nil(t, err)

			//bob receive pubX and newCapsule
			keyBytesDecrypt, err := DecryptKeyGen(bPriKey, newCapsule, pubX)
			assert.Nil(t, err)
			assert.Equal(t, keyBytes, keyBytesDecrypt)

			capsuleAsBytes, err := capsule.Encode()
			assert.Nil(t, err)
			capsuleTest, err := NewCapsuleFromBytes(capsuleAsBytes)
			assert.Nil(t, err)
			assert.True(t, capsule.Equal(capsuleTest))
			capsuleAsBytes2, err := capsuleTest.Encode()
			assert.Nil(t, err)
			assert.Equal(t, capsuleAsBytes, capsuleAsBytes2)
		})
	}
}

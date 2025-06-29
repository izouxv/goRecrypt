package recrypt

import (
	"fmt"
	"testing"

	"github.com/izouxv/goRecrypt/curve"
	"github.com/stretchr/testify/assert"
)

func Test_Recrypt(t *testing.T) {
	// Alice Generate Alice key-pair
	aPriKey, aPubKey, _ := curve.GenerateKeys()
	// Bob Generate Bob key-pair
	bPriKey, bPubKey, _ := curve.GenerateKeys()

	//alice gen key
	capsule, keyBytes, err := EncryptKeyGen(aPubKey)
	assert.Nil(t, err)

	//alice gen pubX to bob
	rk, pubX, err := ReKeyGen(aPriKey, bPubKey)
	assert.Nil(t, err)
	fmt.Println("rk:", rk)

	// Server executes re-encrypt
	newCapsule, err := ReEncryption(rk, capsule)
	assert.Nil(t, err)

	//bob receive pubX and newCapsule
	keyBytesDecrypt, err := DecryptKeyGen(bPriKey, newCapsule, pubX)
	assert.Nil(t, err)

	assert.Equal(t, keyBytes, keyBytesDecrypt)

	capsuleAsBytes, err := EncodeCapsule(*capsule)
	assert.Nil(t, err)
	capsuleTest, err := DecodeCapsule(capsuleAsBytes)
	assert.Nil(t, err)
	capsuleAsBytes2, err := EncodeCapsule(capsuleTest)
	assert.Nil(t, err)
	assert.Equal(t, capsuleAsBytes, capsuleAsBytes2)
}

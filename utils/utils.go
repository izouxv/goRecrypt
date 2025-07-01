package utils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/izouxv/goRecrypt/curve"
	"golang.org/x/crypto/sha3"
)

// concat bytes
func ConcatBytes(a, b []byte) []byte {
	var buf bytes.Buffer
	buf.Write(a)
	buf.Write(b)
	return buf.Bytes()
}

// convert message to hash value
func Sha3Hash(message []byte) ([]byte, error) {
	sha := sha3.New256()
	_, err := sha.Write(message)
	if err != nil {
		return nil, err
	}
	return sha.Sum(nil), nil
}

// map hash value to curve
func HashToCurve(CURVE elliptic.Curve, hash []byte) *big.Int {
	hashInt := new(big.Int).SetBytes(hash)
	return hashInt.Mod(hashInt, CURVE.Params().N)
}

// convert private key to string
func PrivateKeyToString(privateKey *ecdsa.PrivateKey) []byte {
	return privateKey.D.Bytes()
}

// convert string to private key
func PrivateKeyBytesToKey(CURVE elliptic.Curve, priKeyAsBytes []byte) (*ecdsa.PrivateKey, error) {
	// priKeyAsBytes, err := hex.DecodeString(privateKeyStr)
	// if err != nil {
	// 	return nil, err
	// }
	d := new(big.Int).SetBytes(priKeyAsBytes)
	// compute public key
	x, y := CURVE.ScalarBaseMult(priKeyAsBytes)
	pubKey := ecdsa.PublicKey{
		CURVE, x, y,
	}
	key := &ecdsa.PrivateKey{
		D:         d,
		PublicKey: pubKey,
	}
	return key, nil
}

// convert public key to string
func PublicKeyToBytes(publicKey *ecdsa.PublicKey) []byte {
	pubKeyBytes := curve.PointToBytes(publicKey.Curve, publicKey)
	return pubKeyBytes
}

// convert public key string to key
func PublicKeyBytesToKey(CURVE elliptic.Curve, pubKeyAsBytes []byte) (*ecdsa.PublicKey, error) {
	// pubKeyAsBytes, err := hex.DecodeString(pubKey)
	// if err != nil {
	// 	return nil, err
	// }
	// x, y := elliptic.Unmarshal(CURVE, pubKeyAsBytes)
	x, y := elliptic.UnmarshalCompressed(CURVE, pubKeyAsBytes)
	key := &ecdsa.PublicKey{
		Curve: CURVE,
		X:     x,
		Y:     y,
	}
	return key, nil
}

func GenerateSeed(size int) ([]byte, error) {
	if size < 16 || size > 64 {
		return nil, fmt.Errorf("seed size must be between 16 and 64 bytes, but got %d", size)
	}
	seed := make([]byte, size)
	_, err := rand.Read(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}
	return seed, nil
}

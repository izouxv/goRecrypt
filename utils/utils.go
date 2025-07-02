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

// GenerateKeys creates a new ECDSA private and public key pair.
func GenerateKeys(CURVE elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(CURVE, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// ConcatBytes concatenates two byte slices.
func ConcatBytes(a, b []byte) []byte {
	var buf bytes.Buffer
	buf.Write(a)
	buf.Write(b)
	return buf.Bytes()
}

// Sha3Hash converts a message to a hash value using SHA3-256.
func Sha3Hash(message []byte) ([]byte, error) {
	sha := sha3.New256()
	_, err := sha.Write(message)
	if err != nil {
		return nil, err
	}
	return sha.Sum(nil), nil
}

// HashToCurve maps a hash value to a big.Int on the curve.
func HashToCurve(CURVE elliptic.Curve, hash []byte) *big.Int {
	hashInt := new(big.Int).SetBytes(hash)
	return hashInt.Mod(hashInt, CURVE.Params().N)
}

// PrivateKeyToBytes converts a private key to its byte representation (the D value).
func PrivateKeyToBytes(privateKey *ecdsa.PrivateKey) []byte {
	return privateKey.D.Bytes()
}

// PrivateKeyFromBytes converts a byte slice to a private key.
func PrivateKeyFromBytes(CURVE elliptic.Curve, priKeyAsBytes []byte) (*ecdsa.PrivateKey, error) {
	d := new(big.Int).SetBytes(priKeyAsBytes)
	// Compute public key.
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

// PublicKeyToBytes converts a public key to its compressed byte representation.
func PublicKeyToBytes(publicKey *ecdsa.PublicKey) []byte {
	pubKeyBytes := curve.PointToBytes(publicKey.Curve, publicKey)
	return pubKeyBytes
}

// PublicKeyFromBytes converts a byte slice to a public key.
func PublicKeyFromBytes(CURVE elliptic.Curve, pubKeyAsBytes []byte) (*ecdsa.PublicKey, error) {
	return curve.BytesToPoint(CURVE, pubKeyAsBytes)
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

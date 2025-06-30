package recrypt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/izouxv/goRecrypt/curve"
	"github.com/izouxv/goRecrypt/math"
	"github.com/izouxv/goRecrypt/utils"
)

type Capsule struct {
	E *ecdsa.PublicKey
	V *ecdsa.PublicKey
	S *big.Int
}

func (c *Capsule) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	utils.WriteVarBytes(buf, curve.PointToBytes(c.E))
	utils.WriteVarBytes(buf, curve.PointToBytes(c.V))
	utils.WriteVarBytes(buf, c.S.Bytes())
	return buf.Bytes(), nil
}

func (c *Capsule) Decode(data []byte) error {
	buf := bytes.NewBuffer(data)

	decode := func() (*ecdsa.PublicKey, error) {
		kStr, _, err := utils.ReadVarBytes(buf)
		if err != nil {
			return nil, err
		}
		k := new(ecdsa.PublicKey)
		k.Curve = curve.CURVE()
		k.X, k.Y = elliptic.Unmarshal(curve.CURVE(), kStr)
		return k, nil
	}

	k, err := decode()
	if err != nil {
		return err
	}
	c.E = k

	k, err = decode()
	if err != nil {
		return err
	}
	c.V = k

	sStr, _, err := utils.ReadVarBytes(buf)
	if err != nil {
		return err
	}

	y := new(big.Int).SetBytes(sStr)
	c.S = y
	return nil

}

func EncryptKeyGen(pubKey *ecdsa.PublicKey) (capsule *Capsule, keyBytes []byte, err error) {
	s := new(big.Int)
	// generate E,V key-pairs
	priE, pubE, err := curve.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}
	priV, pubV, err := curve.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}
	// get H2(E || V)
	h := utils.HashToCurve(
		utils.ConcatBytes(
			curve.PointToBytes(pubE),
			curve.PointToBytes(pubV)))
	// get s = v + e * H2(E || V)
	s = math.BigIntAdd(priV.D, math.BigIntMul(priE.D, h))
	// get (pk_A)^{e+v}
	point := curve.PointScalarMul(pubKey, math.BigIntAdd(priE.D, priV.D))
	// generate aes key
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, nil, err
	}
	capsule = &Capsule{
		E: pubE,
		V: pubV,
		S: s,
	}
	fmt.Println("old key:", hex.EncodeToString(keyBytes))
	return capsule, keyBytes, nil
}

// Recreate aes key
func RecreateAESKeyByMyPriKey(capsule *Capsule, aPriKey *ecdsa.PrivateKey) (keyBytes []byte, err error) {
	point1 := curve.PointScalarAdd(capsule.E, capsule.V)
	point := curve.PointScalarMul(point1, aPriKey.D)
	// generate aes key
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

func RecreateAESKeyByMyPriKeyStr(capsule *Capsule, aPriKeyStr string) (keyBytes []byte, err error) {
	aPriKey, err := utils.PrivateKeyStrToKey(aPriKeyStr)
	if err != nil {
		return nil, err
	}
	return RecreateAESKeyByMyPriKey(capsule, aPriKey)
}

func EncryptMessageByAESKey(message []byte, keyBytes []byte) (cipherText []byte, err error) {
	key := hex.EncodeToString(keyBytes)
	// use aes gcm algorithm to encrypt
	// mark keyBytes[:12] as nonce
	cipherText, err = GCMEncrypt(message, key[:32], keyBytes[:12], nil)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

// Encrypt the message
// AES GCM + Proxy Re-Encryption
func Encrypt(message string, pubKey *ecdsa.PublicKey) (cipherText []byte, capsule *Capsule, err error) {
	capsule, keyBytes, err := EncryptKeyGen(pubKey)
	if err != nil {
		return nil, nil, err
	}
	key := hex.EncodeToString(keyBytes)
	// use aes gcm algorithm to encrypt
	// mark keyBytes[:12] as nonce
	cipherText, err = GCMEncrypt([]byte(message), key[:32], keyBytes[:12], nil)
	if err != nil {
		return nil, nil, err
	}
	return cipherText, capsule, nil
}

func EncryptByStr(message, pubKeyStr string) (cipherText []byte, capsule *Capsule, err error) {
	key, err := utils.PublicKeyStrToKey(pubKeyStr)
	if err != nil {
		return nil, nil, err
	}
	return Encrypt(message, key)
}

// encrypt file
func EncryptFile(inputFile, outPutFile string, pubKey *ecdsa.PublicKey) (capsule *Capsule, err error) {
	capsule, keyBytes, err := EncryptKeyGen(pubKey)
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(keyBytes)
	// use aes ofb algorithm to encrypt
	// mark keyBytes[:16] as nonce
	err = OFBFileEncrypt(key[:32], keyBytes[:16], inputFile, outPutFile)
	if err != nil {
		return nil, err
	}
	return capsule, nil
}

// encrypt file by pubkey str
func EncryptFileByStr(inputFile, outPutFile, pubKeyStr string) (capsule *Capsule, err error) {
	key, err := utils.PublicKeyStrToKey(pubKeyStr)
	if err != nil {
		return nil, err
	}
	return EncryptFile(inputFile, outPutFile, key)
}

// generate re-encryption key and sends it to Server
// rk = sk_A * d^{-1}
func ReKeyGen(aPriKey *ecdsa.PrivateKey, bPubKey *ecdsa.PublicKey) (*big.Int, *ecdsa.PublicKey, error) {
	// generate x,X key-pair
	priX, pubX, err := curve.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}
	// get d = H3(X_A || pk_B || pk_B^{x_A})
	point := curve.PointScalarMul(bPubKey, priX.D)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(pubX),
				curve.PointToBytes(bPubKey)),
			curve.PointToBytes(point)))
	// rk = sk_A * d^{-1}
	rk := math.BigIntMul(aPriKey.D, math.GetInvert(d))
	rk.Mod(rk, curve.N)
	return rk, pubX, nil
}

func ReKeyGenByStr(aPriKeyStr, bPubKeyStr string) (*big.Int, *ecdsa.PublicKey, error) {
	aPriKey, err := utils.PrivateKeyStrToKey(aPriKeyStr)
	if err != nil {
		return nil, nil, err
	}
	bPubKey, err := utils.PublicKeyStrToKey(bPubKeyStr)
	if err != nil {
		return nil, nil, err
	}
	return ReKeyGen(aPriKey, bPubKey)
}

// Server executes Re-Encryption method
func ReEncryption(rk *big.Int, capsule *Capsule) (*Capsule, error) {
	// check g^s == V * E^{H2(E || V)}
	x1, y1 := curve.CURVE().ScalarBaseMult(capsule.S.Bytes())
	tempX, tempY := curve.CURVE().ScalarMult(capsule.E.X, capsule.E.Y,
		utils.HashToCurve(
			utils.ConcatBytes(
				curve.PointToBytes(capsule.E),
				curve.PointToBytes(capsule.V))).Bytes())
	x2, y2 := curve.CURVE().Add(capsule.V.X, capsule.V.Y, tempX, tempY)
	// if check failed return error
	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		return nil, fmt.Errorf("%s", "Capsule not match")
	}
	// E' = E^{rk}, V' = V^{rk}
	newCapsule := &Capsule{
		E: curve.PointScalarMul(capsule.E, rk),
		V: curve.PointScalarMul(capsule.V, rk),
		S: capsule.S,
	}
	return newCapsule, nil
}

func DecryptKeyGen(bPriKey *ecdsa.PrivateKey, capsule *Capsule, pubX *ecdsa.PublicKey) (keyBytes []byte, err error) {
	// S = X_A^{sk_B}
	S := curve.PointScalarMul(pubX, bPriKey.D)
	// recreate d = H3(X_A || pk_B || S)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(pubX),
				curve.PointToBytes(&bPriKey.PublicKey)),
			curve.PointToBytes(S)))
	point := curve.PointScalarMul(
		curve.PointScalarAdd(capsule.E, capsule.V), d)
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

// Recreate the aes key then decrypt the cipherText
func Decrypt(bPriKey *ecdsa.PrivateKey, capsule *Capsule, pubX *ecdsa.PublicKey, cipherText []byte) (plainText []byte, err error) {
	keyBytes, err := DecryptKeyGen(bPriKey, capsule, pubX)
	if err != nil {
		return nil, err
	}
	// recreate aes key = G((E' * V')^d)
	key := hex.EncodeToString(keyBytes)
	// use aes gcm to decrypt
	// mark keyBytes[:12] as nonce
	plainText, err = GCMDecrypt(cipherText, key[:32], keyBytes[:12], nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func DecryptByStr(bPriKeyStr string, capsule *Capsule, pubXStr string, cipherText []byte) (plainText []byte, err error) {
	bPriKey, err := utils.PrivateKeyStrToKey(bPriKeyStr)
	if err != nil {
		return nil, err
	}
	pubX, err := utils.PublicKeyStrToKey(pubXStr)
	if err != nil {
		return nil, err
	}
	return Decrypt(bPriKey, capsule, pubX, cipherText)
}

// decrypt file
func DecryptFile(inputFile, outPutFile string, bPriKey *ecdsa.PrivateKey, capsule *Capsule, pubX *ecdsa.PublicKey) (err error) {
	keyBytes, err := DecryptKeyGen(bPriKey, capsule, pubX)
	if err != nil {
		return err
	}
	key := hex.EncodeToString(keyBytes)
	// use aes gcm to decrypt
	// mark keyBytes[:16] as nonce
	err = OFBFileDecrypt(key[:32], keyBytes[:16], inputFile, outPutFile)
	if err != nil {
		return err
	}
	return nil
}

// decrypt file by str
func DecryptFileByStr(inputFile, outPutFile string, bPriKeyStr string, capsule *Capsule, pubXStr string) (err error) {
	bPriKey, err := utils.PrivateKeyStrToKey(bPriKeyStr)
	if err != nil {
		return err
	}
	pubX, err := utils.PublicKeyStrToKey(pubXStr)
	if err != nil {
		return err
	}
	return DecryptFile(inputFile, outPutFile, bPriKey, capsule, pubX)
}

// Decrypt by my own private key
func DecryptOnMyPriKey(aPriKey *ecdsa.PrivateKey, capsule *Capsule, cipherText []byte) (plainText []byte, err error) {
	keyBytes, err := RecreateAESKeyByMyPriKey(capsule, aPriKey)
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(keyBytes)
	// use aes gcm algorithm to encrypt
	// mark keyBytes[:12] as nonce
	plainText, err = GCMDecrypt(cipherText, key[:32], keyBytes[:12], nil)
	return plainText, err
}

func DecryptOnMyOwnStrKey(aPriKeyStr string, capsule *Capsule, cipherText []byte) (plainText []byte, err error) {
	aPriKey, err := utils.PrivateKeyStrToKey(aPriKeyStr)
	if err != nil {
		return nil, err
	}
	return DecryptOnMyPriKey(aPriKey, capsule, cipherText)
}

func EncodeCapsule(capsule Capsule) (capsuleAsBytes []byte, err error) {
	return capsule.Encode()
}

func DecodeCapsule(capsuleAsBytes []byte) (capsule Capsule, err error) {
	return capsule, capsule.Decode(capsuleAsBytes)
}

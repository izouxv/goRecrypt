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

func (c *Capsule) Equal(cc *Capsule) bool {
	return c.S.Cmp(cc.S) == 0 && c.E.Equal(cc.E) && c.V.Equal(cc.V)
}

func (c *Capsule) Curve() elliptic.Curve {
	return c.E.Curve
}

func (c *Capsule) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	if err := utils.WriteVarBytes(buf, []byte(c.Curve().Params().Name)); err != nil {
		return nil, err
	}
	if err := utils.WriteVarBytes(buf, curve.PointToBytes(c.E.Curve, c.E)); err != nil {
		return nil, err
	}
	if err := utils.WriteVarBytes(buf, curve.PointToBytes(c.V.Curve, c.V)); err != nil {
		return nil, err
	}
	if err := utils.WriteVarBytes(buf, c.S.Bytes()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *Capsule) Decode(data []byte) error {
	buf := bytes.NewBuffer(data)

	name, _, err := utils.ReadVarBytes(buf)
	if err != nil {
		return err
	}
	CURVE := curve.CurveGet(string(name))

	decode := func() (*ecdsa.PublicKey, error) {
		pubKeyAsBytes, _, err := utils.ReadVarBytes(buf)
		if err != nil {
			return nil, err
		}
		x, y := elliptic.Unmarshal(CURVE, pubKeyAsBytes)
		k := &ecdsa.PublicKey{
			Curve: CURVE,
			X:     x,
			Y:     y,
		}
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
	CURVE := pubKey.Curve

	s := new(big.Int)
	// generate E,V key-pairs
	priE, pubE, err := curve.GenerateKeys(CURVE)
	if err != nil {
		return nil, nil, err
	}
	priV, pubV, err := curve.GenerateKeys(CURVE)
	if err != nil {
		return nil, nil, err
	}
	// get H2(E || V)
	h := utils.HashToCurve(
		CURVE,
		utils.ConcatBytes(
			curve.PointToBytes(CURVE, pubE),
			curve.PointToBytes(CURVE, pubV)))
	// get s = v + e * H2(E || V)
	s = math.BigIntAdd(CURVE, priV.D, math.BigIntMul(CURVE, priE.D, h))
	// get (pk_A)^{e+v}
	point := curve.PointScalarMul(CURVE, pubKey, math.BigIntAdd(CURVE, priE.D, priV.D))
	// generate aes key
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(CURVE, point))
	if err != nil {
		return nil, nil, err
	}
	capsule = &Capsule{
		E: pubE,
		V: pubV,
		S: s,
	}
	// fmt.Println("old key:", hex.EncodeToString(keyBytes))
	return capsule, keyBytes, nil
}

// Recreate aes key
func RecreateAESKeyByMyPriKey(capsule *Capsule, aPriKey *ecdsa.PrivateKey) (keyBytes []byte, err error) {
	CURVE := aPriKey.Curve
	point1 := curve.PointScalarAdd(CURVE, capsule.E, capsule.V)
	point := curve.PointScalarMul(CURVE, point1, aPriKey.D)
	// generate aes key
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(CURVE, point))
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

func RecreateAESKeyByMyPriKeyStr(capsule *Capsule, aPriKeyStr string) (keyBytes []byte, err error) {
	aPriKey, err := utils.PrivateKeyStrToKey(capsule.Curve(), aPriKeyStr)
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

func EncryptByStr(CURVE elliptic.Curve, message, pubKeyStr string) (cipherText []byte, capsule *Capsule, err error) {
	key, err := utils.PublicKeyStrToKey(CURVE, pubKeyStr)
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
func EncryptFileByStr(CURVE elliptic.Curve, inputFile, outPutFile, pubKeyStr string) (capsule *Capsule, err error) {
	key, err := utils.PublicKeyStrToKey(CURVE, pubKeyStr)
	if err != nil {
		return nil, err
	}
	return EncryptFile(inputFile, outPutFile, key)
}

// generate re-encryption key and sends it to Server
// rk = sk_A * d^{-1}
func ReKeyGen(aPriKey *ecdsa.PrivateKey, bPubKey *ecdsa.PublicKey) (*big.Int, *ecdsa.PublicKey, error) {
	CURVE := aPriKey.Curve

	// generate x,X key-pair
	priX, pubX, err := curve.GenerateKeys(CURVE)
	if err != nil {
		return nil, nil, err
	}

	// get d = H3(X_A || pk_B || pk_B^{x_A})
	point := curve.PointScalarMul(CURVE, bPubKey, priX.D)
	d := utils.HashToCurve(
		CURVE,
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(CURVE, pubX),
				curve.PointToBytes(CURVE, bPubKey)),
			curve.PointToBytes(CURVE, point)))
	// rk = sk_A * d^{-1}
	rk := math.BigIntMul(CURVE, aPriKey.D, math.GetInvert(CURVE, d))
	rk.Mod(rk, CURVE.Params().N)
	return rk, pubX, nil
}

func ReKeyGenByStr(CURVE elliptic.Curve, aPriKeyStr, bPubKeyStr string) (*big.Int, *ecdsa.PublicKey, error) {
	aPriKey, err := utils.PrivateKeyStrToKey(CURVE, aPriKeyStr)
	if err != nil {
		return nil, nil, err
	}
	bPubKey, err := utils.PublicKeyStrToKey(CURVE, bPubKeyStr)
	if err != nil {
		return nil, nil, err
	}
	return ReKeyGen(aPriKey, bPubKey)
}

// Server executes Re-Encryption method
func ReEncryption(rk *big.Int, capsule *Capsule) (*Capsule, error) {
	CURVE := capsule.Curve()
	// check g^s == V * E^{H2(E || V)}
	x1, y1 := CURVE.ScalarBaseMult(capsule.S.Bytes())
	tempX, tempY := CURVE.ScalarMult(capsule.E.X, capsule.E.Y,
		utils.HashToCurve(
			CURVE,
			utils.ConcatBytes(
				curve.PointToBytes(CURVE, capsule.E),
				curve.PointToBytes(CURVE, capsule.V))).Bytes())
	x2, y2 := CURVE.Add(capsule.V.X, capsule.V.Y, tempX, tempY)
	// if check failed return error
	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		return nil, fmt.Errorf("%s", "Capsule not match")
	}
	// E' = E^{rk}, V' = V^{rk}
	newCapsule := &Capsule{
		E: curve.PointScalarMul(CURVE, capsule.E, rk),
		V: curve.PointScalarMul(CURVE, capsule.V, rk),
		S: capsule.S,
	}
	return newCapsule, nil
}

func DecryptKeyGen(bPriKey *ecdsa.PrivateKey, capsule *Capsule, pubX *ecdsa.PublicKey) (keyBytes []byte, err error) {
	CURVE := bPriKey.Curve

	// S = X_A^{sk_B}
	S := curve.PointScalarMul(CURVE, pubX, bPriKey.D)
	// recreate d = H3(X_A || pk_B || S)
	d := utils.HashToCurve(
		CURVE,
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(CURVE, pubX),
				curve.PointToBytes(CURVE, &bPriKey.PublicKey)),
			curve.PointToBytes(CURVE, S)))
	point := curve.PointScalarMul(CURVE,
		curve.PointScalarAdd(CURVE, capsule.E, capsule.V), d)
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(CURVE, point))
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
	bPriKey, err := utils.PrivateKeyStrToKey(capsule.Curve(), bPriKeyStr)
	if err != nil {
		return nil, err
	}
	pubX, err := utils.PublicKeyStrToKey(capsule.Curve(), pubXStr)
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
	bPriKey, err := utils.PrivateKeyStrToKey(capsule.Curve(), bPriKeyStr)
	if err != nil {
		return err
	}
	pubX, err := utils.PublicKeyStrToKey(capsule.Curve(), pubXStr)
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
	aPriKey, err := utils.PrivateKeyStrToKey(capsule.Curve(), aPriKeyStr)
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

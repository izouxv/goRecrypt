package pre

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/izouxv/goRecrypt/curve"
	"github.com/izouxv/goRecrypt/utils"
)

const (
	// AES256KeySize is the size of an AES-256 key in bytes.
	AES256KeySize = 32
)

// NewCapsuleFromBytes decodes a byte slice into a Capsule.
// This is a constructor-like function for creating a capsule from its serialized form.
func NewCapsuleFromBytes(data []byte) (*Capsule, error) {
	c := &Capsule{}
	if err := c.Decode(data); err != nil {
		return nil, err
	}
	return c, nil
}

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
	if err := utils.WriteVarBytes(buf, []byte(utils.PublicKeyToBytes(c.E))); err != nil {
		return nil, err
	}
	if err := utils.WriteVarBytes(buf, []byte(utils.PublicKeyToBytes(c.V))); err != nil {
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
		return utils.PublicKeyFromBytes(CURVE, pubKeyAsBytes)
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
	priE, pubE, err := utils.GenerateKeys(CURVE)
	if err != nil {
		return nil, nil, err
	}
	priV, pubV, err := utils.GenerateKeys(CURVE)
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
	s = curve.BigIntAdd(CURVE, priV.D, curve.BigIntMul(CURVE, priE.D, h))
	// get (pk_A)^{e+v}
	point := curve.PointScalarMul(CURVE, pubKey, curve.BigIntAdd(CURVE, priE.D, priV.D))
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
func RecreateAesKeyByMyPriKey(capsule *Capsule, aPriKey *ecdsa.PrivateKey) (keyBytes []byte, err error) {
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

func RecreateAESKeyByMyPriKeyBytes(capsule *Capsule, aPriKeyBytes []byte) (keyBytes []byte, err error) {
	aPriKey, err := utils.PrivateKeyFromBytes(capsule.Curve(), aPriKeyBytes)
	if err != nil {
		return nil, err
	}
	return RecreateAesKeyByMyPriKey(capsule, aPriKey)
}

// generate re-encryption key and sends it to Server
// rk = sk_A * d^{-1}
func ReKeyGen(aPriKey *ecdsa.PrivateKey, bPubKey *ecdsa.PublicKey) (*big.Int, *ecdsa.PublicKey, error) {
	CURVE := aPriKey.Curve

	// generate x,X key-pair
	priX, pubX, err := utils.GenerateKeys(CURVE)
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
	rk := curve.BigIntMul(CURVE, aPriKey.D, curve.GetInvert(CURVE, d))
	rk.Mod(rk, CURVE.Params().N)
	return rk, pubX, nil
}

func ReKeyGenByBytes(CURVE elliptic.Curve, aPriKeyBytes, bPubKeyBytes []byte) (*big.Int, *ecdsa.PublicKey, error) {
	aPriKey, err := utils.PrivateKeyFromBytes(CURVE, aPriKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	bPubKey, err := utils.PublicKeyFromBytes(CURVE, bPubKeyBytes)
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
		return nil, fmt.Errorf("capsule integrity check failed: g^s != V * E^H2(E||V)")
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

package curve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	// _ "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var Curve = make(map[string]elliptic.Curve)

func CurveRegist(curve elliptic.Curve) {
	Curve[curve.Params().Name] = curve
}
func CurveGet(name string) elliptic.Curve {
	return Curve[name]
}

func init() {
	CurveRegist(elliptic.P256())
	CurveRegist(elliptic.P384())
	CurveRegist(elliptic.P521())
}

type CurvePoint = ecdsa.PublicKey

func PointScalarAdd(CURVE elliptic.Curve, a, b *CurvePoint) *CurvePoint {
	x, y := CURVE.Add(a.X, a.Y, b.X, b.Y)
	return &CurvePoint{CURVE, x, y}
}

func PointScalarMul(CURVE elliptic.Curve, a *CurvePoint, k *big.Int) *CurvePoint {
	x, y := a.ScalarMult(a.X, a.Y, k.Bytes())
	return &CurvePoint{CURVE, x, y}
}

func BigIntMulBase(CURVE elliptic.Curve, k *big.Int) *CurvePoint {
	x, y := CURVE.ScalarBaseMult(k.Bytes())
	return &CurvePoint{CURVE, x, y}
}

func PointToBytes(CURVE elliptic.Curve, point *CurvePoint) (res []byte) {
	// res = elliptic.Marshal(CURVE, point.X, point.Y)
	res = elliptic.MarshalCompressed(CURVE, point.X, point.Y)
	return
}

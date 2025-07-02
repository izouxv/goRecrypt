package curve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Curve is a map of registered elliptic curves, keyed by their name.
var Curve = make(map[string]elliptic.Curve)

// CurveRegist registers a curve so it can be looked up by name.
func CurveRegist(curve elliptic.Curve) {
	if _, ok := Curve[curve.Params().Name]; ok {
		panic("curve already registered")
	}
	Curve[curve.Params().Name] = curve
}

// CurveGet retrieves a registered curve by its name.
func CurveGet(name string) elliptic.Curve {
	return Curve[name]
}

func init() {
	CurveRegist(elliptic.P256())
	CurveRegist(elliptic.P384())
	CurveRegist(elliptic.P521())
	CurveRegist(secp256k1.S256())
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
	// Use the compressed format for efficiency.
	res = elliptic.MarshalCompressed(CURVE, point.X, point.Y)
	// res = elliptic.Marshal(CURVE, point.X, point.Y)
	return
}
func BytesToPoint(CURVE elliptic.Curve, pubKeyAsBytes []byte) (*CurvePoint, error) {
	// The generic implementation of elliptic.UnmarshalCompressed in the standard library
	// assumes a curve of the form y² = x³ - 3x + b. This is incorrect for secp256k1,
	// whose equation is y² = x³ + 7 (where a=0).
	// We must use the secp256k1 library's own parsing function for this curve.
	if CURVE.Params().Name == secp256k1.S256().Params().Name {
		pubKey, err := secp256k1.ParsePubKey(pubKeyAsBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse secp256k1 public key: %w", err)
		}
		ecdsaKey := pubKey.ToECDSA()
		return &CurvePoint{CURVE, ecdsaKey.X, ecdsaKey.Y}, nil
	}

	x, y := elliptic.UnmarshalCompressed(CURVE, pubKeyAsBytes)
	if x == nil { // y will be nil if x is.
		return nil, fmt.Errorf("invalid public key bytes for curve %s", CURVE.Params().Name)
	}
	return &CurvePoint{CURVE, x, y}, nil
}

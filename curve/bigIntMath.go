package curve

import (
	"crypto/elliptic"
	"math/big"
)

func BigIntAdd(CURVE elliptic.Curve, a, b *big.Int) (res *big.Int) {
	res = new(big.Int).Add(a, b)
	res.Mod(res, CURVE.Params().N)
	return
}

func BigIntSub(CURVE elliptic.Curve, a, b *big.Int) (res *big.Int) {
	res = new(big.Int)
	res.Sub(a, b)
	res.Mod(res, CURVE.Params().N)
	return
}

func BigIntMul(CURVE elliptic.Curve, a, b *big.Int) (res *big.Int) {
	res = new(big.Int).Mul(a, b)
	res.Mod(res, CURVE.Params().N)
	return
}

func GetInvert(CURVE elliptic.Curve, a *big.Int) (res *big.Int) {
	res = new(big.Int).ModInverse(a, CURVE.Params().N)
	return
}

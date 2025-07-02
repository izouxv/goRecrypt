package shamir

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Share represents a share of a secret.
type Share struct {
	X *big.Int
	Y *big.Int
}

// Split takes a secret and splits it into n shares, with a threshold of t.
// The arithmetic is performed modulo the given prime.
func Split(secret *big.Int, n, t int, prime *big.Int) ([]*Share, error) {
	if t <= 1 || n < t {
		return nil, fmt.Errorf("invalid parameters: n must be >= t and t must be > 1")
	}

	// Create a random polynomial of degree t-1.
	// f(x) = secret + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
	coeffs := make([]*big.Int, t)
	coeffs[0] = secret
	for i := 1; i < t; i++ {
		c, err := rand.Int(rand.Reader, prime)
		if err != nil {
			return nil, err
		}
		coeffs[i] = c
	}

	// Generate n shares by evaluating the polynomial at x = 1, 2, ..., n.
	shares := make([]*Share, n)
	for i := 1; i <= n; i++ {
		x := big.NewInt(int64(i))
		y := new(big.Int)
		xPowJ := big.NewInt(1)

		for j := 0; j < t; j++ {
			term := new(big.Int).Mul(coeffs[j], xPowJ)
			y.Add(y, term)
			xPowJ.Mul(xPowJ, x)
			xPowJ.Mod(xPowJ, prime)
		}
		y.Mod(y, prime)
		shares[i-1] = &Share{X: x, Y: y}
	}

	return shares, nil
}

// Combine takes a list of shares and reconstructs the secret.
func Combine(shares []*Share, prime *big.Int) (*big.Int, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}

	secret := new(big.Int)

	for i, shareI := range shares {
		// Calculate Lagrange basis polynomial l_i(0)
		num := big.NewInt(1)
		den := big.NewInt(1)

		for j, shareJ := range shares {
			if i == j {
				continue
			}
			num.Mul(num, shareJ.X)
			den.Mul(den, new(big.Int).Sub(shareJ.X, shareI.X))
		}

		lIAt0 := new(big.Int).ModInverse(den, prime)
		lIAt0.Mul(lIAt0, num)
		lIAt0.Mod(lIAt0, prime)

		term := new(big.Int).Mul(shareI.Y, lIAt0)
		secret.Add(secret, term)
		secret.Mod(secret, prime)
	}

	return secret, nil
}

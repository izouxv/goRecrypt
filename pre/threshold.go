package pre

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/izouxv/goRecrypt/curve"
	"github.com/izouxv/goRecrypt/shamir"
	"github.com/izouxv/goRecrypt/utils"
)

// ReKeyShare is a share of a re-encryption key, suitable for a single proxy.
type ReKeyShare = shamir.Share

// PartialCapsule is a capsule that has been partially re-encrypted by a single proxy.
// It includes the original X value from the re-key share, which is necessary for recombination.
type PartialCapsule struct {
	E *ecdsa.PublicKey
	V *ecdsa.PublicKey
	S *big.Int
	X *big.Int // The X value from the re-key share used.
}

// Encode serializes the PartialCapsule into a byte slice.
func (pc *PartialCapsule) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	// Write curve name first for context during decoding
	if err := utils.WriteVarBytes(buf, []byte(pc.E.Curve.Params().Name)); err != nil {
		return nil, err
	}
	// Write E, V, S, X
	if err := utils.WriteVarBytes(buf, utils.PublicKeyToBytes(pc.E)); err != nil {
		return nil, err
	}
	if err := utils.WriteVarBytes(buf, utils.PublicKeyToBytes(pc.V)); err != nil {
		return nil, err
	}
	if err := utils.WriteVarBytes(buf, pc.S.Bytes()); err != nil {
		return nil, err
	}
	if err := utils.WriteVarBytes(buf, pc.X.Bytes()); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Decode deserializes a byte slice into the PartialCapsule.
func (pc *PartialCapsule) Decode(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read curve name
	name, _, err := utils.ReadVarBytes(buf)
	if err != nil {
		return err
	}
	CURVE := curve.CurveGet(string(name))
	if CURVE == nil {
		return fmt.Errorf("unsupported curve: %s", string(name))
	}

	// Helper to decode a public key
	decodePubKey := func() (*ecdsa.PublicKey, error) {
		pubKeyAsBytes, _, err := utils.ReadVarBytes(buf)
		if err != nil {
			return nil, err
		}
		return utils.PublicKeyFromBytes(CURVE, pubKeyAsBytes)
	}

	// Helper to decode a big.Int
	decodeBigInt := func() (*big.Int, error) {
		bytes, _, err := utils.ReadVarBytes(buf)
		if err != nil {
			return nil, err
		}
		return new(big.Int).SetBytes(bytes), nil
	}

	// Decode E, V, S, X
	if pc.E, err = decodePubKey(); err != nil {
		return err
	}
	if pc.V, err = decodePubKey(); err != nil {
		return err
	}
	if pc.S, err = decodeBigInt(); err != nil {
		return err
	}
	if pc.X, err = decodeBigInt(); err != nil {
		return err
	}

	return nil
}

// ThresholdReKeyGen generates n re-encryption key shares, with a threshold of t.
// It splits the original re-encryption key into n shares using Shamir's Secret Sharing.
func ThresholdReKeyGen(aPriKey *ecdsa.PrivateKey, bPubKey *ecdsa.PublicKey, n, t int) ([]*ReKeyShare, *ecdsa.PublicKey, error) {
	// 1. Generate the original, single re-encryption key `rk`.
	rk, pubX, err := ReKeyGen(aPriKey, bPubKey)
	if err != nil {
		return nil, nil, err
	}

	// 2. Split `rk` into n shares with a threshold of t.
	// The arithmetic is done modulo the curve's order N.
	shares, err := shamir.Split(rk, n, t, aPriKey.Curve.Params().N)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to split re-key: %w", err)
	}

	return shares, pubX, nil
}

// PartialReEncryption is executed by a proxy. It takes a re-key share and a capsule
// and performs a partial re-encryption, returning a PartialCapsule.
func PartialReEncryption(rkShare *ReKeyShare, capsule *Capsule) (*PartialCapsule, error) {
	// The actual re-key share value is rkShare.Y
	reEncryptedCapsule, err := ReEncryption(rkShare.Y, capsule)
	if err != nil {
		return nil, err
	}

	return &PartialCapsule{
		E: reEncryptedCapsule.E,
		V: reEncryptedCapsule.V,
		S: reEncryptedCapsule.S,
		X: rkShare.X,
	}, nil
}

// CombineCapsules takes a list of at least `t` partial capsules and combines them
// into a final, fully re-encrypted capsule that Bob can decrypt.
func CombineCapsules(partialCapsules []*PartialCapsule, CURVE elliptic.Curve) (*Capsule, error) {
	if len(partialCapsules) == 0 {
		return nil, fmt.Errorf("no partial capsules provided")
	}

	prime := CURVE.Params().N

	finalE := &ecdsa.PublicKey{Curve: CURVE, X: new(big.Int), Y: new(big.Int)} // Point at infinity
	finalV := &ecdsa.PublicKey{Curve: CURVE, X: new(big.Int), Y: new(big.Int)} // Point at infinity

	for i, pCapI := range partialCapsules {
		// Calculate Lagrange basis polynomial l_i(0)
		num := big.NewInt(1)
		den := big.NewInt(1)

		for j, pCapJ := range partialCapsules {
			if i == j {
				continue
			}
			num.Mul(num, pCapJ.X)
			den.Mul(den, new(big.Int).Sub(pCapJ.X, pCapI.X))
		}

		lIAt0 := new(big.Int).ModInverse(den, prime)
		lIAt0.Mul(lIAt0, num)
		lIAt0.Mod(lIAt0, prime)

		termE := curve.PointScalarMul(CURVE, pCapI.E, lIAt0)
		termV := curve.PointScalarMul(CURVE, pCapI.V, lIAt0)

		finalE = curve.PointScalarAdd(CURVE, finalE, termE)
		finalV = curve.PointScalarAdd(CURVE, finalV, termV)
	}

	return &Capsule{
		E: finalE,
		V: finalV,
		S: partialCapsules[0].S, // S is the same across all partial capsules
	}, nil
}

// MarshalReKeyShare serializes a ReKeyShare into a byte slice.
func MarshalReKeyShare(share *ReKeyShare) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := utils.WriteVarBytes(buf, share.X.Bytes()); err != nil {
		return nil, err
	}
	if err := utils.WriteVarBytes(buf, share.Y.Bytes()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalReKeyShare deserializes a byte slice into a ReKeyShare.
func UnmarshalReKeyShare(data []byte) (*ReKeyShare, error) {
	buf := bytes.NewBuffer(data)

	xBytes, _, err := utils.ReadVarBytes(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read X value: %w", err)
	}
	yBytes, _, err := utils.ReadVarBytes(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read Y value: %w", err)
	}

	return &ReKeyShare{
		X: new(big.Int).SetBytes(xBytes),
		Y: new(big.Int).SetBytes(yBytes),
	}, nil
}

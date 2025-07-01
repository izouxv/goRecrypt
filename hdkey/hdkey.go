package hdkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
	"strconv"
	"strings"

	"github.com/izouxv/goRecrypt/curve"
	"golang.org/x/crypto/ripemd160"
)

const (
	// HardenedKeyStart is the index at which hardened keys start. (BIP32)
	HardenedKeyStart uint32 = 0x80000000
	// masterKey is the HMAC key used to derive the master key from the seed.
	masterKey = "Bitcoin seed"
)

var (
	// ErrInvalidSeedLen is returned when the seed length is invalid.
	ErrInvalidSeedLen = errors.New("invalid seed length, must be between 16 and 64 bytes")
	// ErrInvalidKey is returned when a derived key is invalid.
	ErrInvalidKey = errors.New("invalid key")
	// ErrCannotDeriveHardenedFromPublic is returned when trying to derive a hardened child from a public key.
	ErrCannotDeriveHardenedFromPublic = errors.New("cannot derive a hardened child from a public key")
	// ErrInvalidDerivationPath is returned for an invalid derivation path.
	ErrInvalidDerivationPath = errors.New("invalid derivation path")
)

// Key represents an HD key.
type Key struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	ChainCode  []byte
	Depth      byte
	Index      uint32
	ParentFP   []byte // Fingerprint of the parent key.
	Curve      elliptic.Curve
}

// NewMaster creates a new master key from a seed.
func NewMaster(seed []byte, c elliptic.Curve) (*Key, error) {
	if len(seed) < 16 || len(seed) > 64 {
		return nil, ErrInvalidSeedLen
	}

	// I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
	hmac := hmac.New(sha512.New, []byte(masterKey))
	_, err := hmac.Write(seed)
	if err != nil {
		return nil, err
	}
	i := hmac.Sum(nil)

	// Split I into two 32-byte sequences, I_L and I_R.
	iL := i[:32]
	iR := i[32:]

	// The master private key is I_L.
	privateKeyD := new(big.Int).SetBytes(iL)

	// Check if the key is valid for the curve.
	if privateKeyD.Cmp(c.Params().N) >= 0 || privateKeyD.Sign() == 0 {
		return nil, ErrInvalidKey
	}

	pubX, pubY := c.ScalarBaseMult(iL)
	ecdsaPriv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: c,
			X:     pubX,
			Y:     pubY,
		},
		D: privateKeyD,
	}

	return &Key{
		PrivateKey: ecdsaPriv,
		PublicKey:  &ecdsaPriv.PublicKey,
		ChainCode:  iR,
		Depth:      0,
		Index:      0,
		ParentFP:   []byte{0x00, 0x00, 0x00, 0x00},
		Curve:      c,
	}, nil
}

// Derive derives a child key from the current key.
func (k *Key) Derive(index uint32) (*Key, error) {
	// Public keys cannot be used to derive hardened child keys.
	if k.PrivateKey == nil && index >= HardenedKeyStart {
		return nil, ErrCannotDeriveHardenedFromPublic
	}

	var data []byte
	if index >= HardenedKeyStart {
		// Hardened derivation: 0x00 || ser256(k_par) || ser32(i)
		data = make([]byte, 1+32+4)
		data[0] = 0x00
		// Ensure the private key D is padded to 32 bytes.
		privKeyBytes := k.PrivateKey.D.Bytes()
		copy(data[1+(32-len(privKeyBytes)):], privKeyBytes)
		binary.BigEndian.PutUint32(data[33:], index)
	} else {
		// Normal derivation: serP(K_par) || ser32(i)
		pubKeyBytes := curve.PointToBytes(k.Curve, k.PublicKey)
		data = make([]byte, len(pubKeyBytes)+4)
		copy(data, pubKeyBytes)
		binary.BigEndian.PutUint32(data[len(pubKeyBytes):], index)
	}

	// I = HMAC-SHA512(Key = c_par, Data = data)
	hmac := hmac.New(sha512.New, k.ChainCode)
	_, err := hmac.Write(data)
	if err != nil {
		return nil, err
	}
	i := hmac.Sum(nil)
	iL := i[:32]
	iR := i[32:]

	parseIL := new(big.Int).SetBytes(iL)

	// If parseI_L >= n, the key is invalid, and we should proceed with the next value of i.
	if parseIL.Cmp(k.Curve.Params().N) >= 0 {
		// This is a rare case, but the BIP32 spec requires retrying. For simplicity, we return an error.
		// A more robust implementation might loop here.
		return nil, ErrInvalidKey
	}

	var childPriv *ecdsa.PrivateKey
	var childPub *ecdsa.PublicKey

	if k.PrivateKey != nil {
		// Child private key: (parseI_L + k_par) mod n
		childPrivKeyD := new(big.Int).Add(parseIL, k.PrivateKey.D)
		childPrivKeyD.Mod(childPrivKeyD, k.Curve.Params().N)

		// If the child private key is 0, it's invalid.
		if childPrivKeyD.Sign() == 0 {
			return nil, ErrInvalidKey
		}

		pubX, pubY := k.Curve.ScalarBaseMult(childPrivKeyD.Bytes())
		childPriv = &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: k.Curve, X: pubX, Y: pubY},
			D:         childPrivKeyD,
		}
		childPub = &childPriv.PublicKey
	} else {
		// Child public key: point(parseI_L) + K_par
		ilX, ilY := k.Curve.ScalarBaseMult(iL)
		pubX, pubY := k.Curve.Add(ilX, ilY, k.PublicKey.X, k.PublicKey.Y)

		// Check if the resulting point is the point at infinity.
		if pubX.Sign() == 0 && pubY.Sign() == 0 {
			return nil, ErrInvalidKey
		}

		childPub = &ecdsa.PublicKey{Curve: k.Curve, X: pubX, Y: pubY}
	}

	return &Key{
		PrivateKey: childPriv,
		PublicKey:  childPub,
		ChainCode:  iR,
		Depth:      k.Depth + 1,
		Index:      index,
		ParentFP:   k.Fingerprint(),
		Curve:      k.Curve,
	}, nil
}

// Neuter creates a new key with the private key removed (i.e., a public-only key).
func (k *Key) Neuter() (*Key, error) {
	return &Key{
		PublicKey: k.PublicKey,
		ChainCode: k.ChainCode,
		Depth:     k.Depth,
		Index:     k.Index,
		ParentFP:  k.ParentFP,
		Curve:     k.Curve,
	}, nil
}

// Fingerprint calculates the key's fingerprint.
// The fingerprint is the first 4 bytes of the HASH160 of the compressed public key.
func (k *Key) Fingerprint() []byte {
	// HASH160 = RIPEMD160(SHA256(data))
	pubKeyBytes := curve.PointToBytes(k.Curve, k.PublicKey)

	sha256Hasher := sha256.New()
	sha256Hasher.Write(pubKeyBytes)
	sha256Hash := sha256Hasher.Sum(nil)

	ripemd160Hasher := ripemd160.New()
	ripemd160Hasher.Write(sha256Hash)
	ripemd160Hash := ripemd160Hasher.Sum(nil)

	return ripemd160Hash[:4]
}

// DerivePath parses a BIP32-style derivation path and derives the corresponding key.
// The path should be in the format "m/0'/1/2'/2/1000000000".
// The "m" prefix is optional for non-master keys and will be ignored.
func (k *Key) DerivePath(path string) (*Key, error) {
	// If the path is "m" or "M", it refers to the master key itself.
	if path == "m" || path == "M" {
		// We can't derive the master key from a child key.
		if k.Depth != 0 {
			return nil, ErrInvalidDerivationPath
		}
		return k, nil
	}

	segments := strings.Split(path, "/")

	if strings.ToLower(segments[0]) == "m" {
		if k.Depth != 0 {
			return nil, ErrInvalidDerivationPath
		}
		segments = segments[1:]
	}

	currentKey := k
	for _, segment := range segments {
		var index uint32
		var err error
		// Check for the hardened key marker (' or h).
		if strings.HasSuffix(segment, "'") || strings.HasSuffix(segment, "h") {
			val, errParse := strconv.ParseUint(segment[:len(segment)-1], 10, 32)
			if errParse != nil {
				return nil, ErrInvalidDerivationPath
			}
			index = uint32(val) + HardenedKeyStart
		} else {
			val, errParse := strconv.ParseUint(segment, 10, 32)
			if errParse != nil {
				return nil, ErrInvalidDerivationPath
			}
			index = uint32(val)
		}

		currentKey, err = currentKey.Derive(index)
		if err != nil {
			return nil, err
		}
	}

	return currentKey, nil
}

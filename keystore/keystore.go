package keystore

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/izouxv/goRecrypt/curve"
	"github.com/izouxv/goRecrypt/pre"
	"github.com/izouxv/goRecrypt/utils"
	"golang.org/x/crypto/scrypt"
)

const (
	keyHeaderKDF = "scrypt"
	version      = 1
)

// ScryptN is the N parameter of Scrypt encryption algorithm, using 2^18 per recommendation for standard security.
// For testing, a smaller value can be used to speed up execution.
var ScryptN = 1 << 18

// ScryptP is the P parameter of Scrypt encryption algorithm, using 1 per recommendation.
var ScryptP = 1

var (
	// ErrInvalidPassword is returned when the password for decryption is incorrect.
	ErrInvalidPassword = errors.New("invalid password")
)

// Key is the top-level structure for a keystore file.
type Key struct {
	ID        string     `json:"id"`
	Version   int        `json:"version"`
	Crypto    CryptoJSON `json:"crypto"`
	CurveName string     `json:"curve"`
}

// CryptoJSON contains the cryptographic parameters.
type CryptoJSON struct {
	Cipher     string           `json:"cipher"`
	CipherText []byte           `json:"ciphertext"`
	KDF        string           `json:"kdf"`
	KDFParams  ScryptParamsJSON `json:"kdfparams"`
}

// ScryptParamsJSON contains the parameters for the scrypt KDF.
type ScryptParamsJSON struct {
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	Dklen int    `json:"dklen"`
	Salt  []byte `json:"salt"`
}

// EncryptKey encrypts a private key using a password and scrypt KDF,
// returning the JSON-encoded keystore file bytes.
func EncryptKey(key *ecdsa.PrivateKey, password string) ([]byte, error) {
	// Get the private key bytes (D value)
	privKeyBytes := utils.PrivateKeyToBytes(key)

	// Generate a random salt for scrypt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// Derive the encryption key from the password using scrypt
	// We derive a 32-byte key for AES-256-GCM.
	const dklen = 32
	derivedKey, err := scrypt.Key([]byte(password), salt, ScryptN, 8, ScryptP, dklen)
	if err != nil {
		return nil, err
	}

	// Encrypt the private key using AES-256-GCM
	cipherText, err := pre.GCMEncrypt(privKeyBytes, derivedKey, nil)
	if err != nil {
		return nil, err
	}

	// Create the keystore JSON object
	keystore := &Key{
		ID:        uuid.New().String(),
		Version:   version,
		CurveName: key.Curve.Params().Name,
		Crypto: CryptoJSON{
			Cipher:     "aes-256-gcm",
			CipherText: cipherText,
			KDF:        keyHeaderKDF,
			KDFParams: ScryptParamsJSON{
				N:     ScryptN,
				R:     8,
				P:     ScryptP,
				Dklen: dklen,
				Salt:  salt,
			},
		},
	}

	return json.MarshalIndent(keystore, "", "  ")
}

// DecryptKey decrypts a keystore file using a password.
func DecryptKey(keystoreBytes []byte, password string) (*ecdsa.PrivateKey, error) {
	// Unmarshal the keystore JSON
	var key Key
	if err := json.Unmarshal(keystoreBytes, &key); err != nil {
		return nil, err
	}

	// Check KDF and Cipher
	if key.Crypto.KDF != keyHeaderKDF {
		return nil, fmt.Errorf("unsupported KDF: %s", key.Crypto.KDF)
	}
	if key.Crypto.Cipher != "aes-256-gcm" {
		return nil, fmt.Errorf("unsupported cipher: %s", key.Crypto.Cipher)
	}

	// Re-derive the key from the password and stored salt
	kdfParams := key.Crypto.KDFParams
	derivedKey, err := scrypt.Key([]byte(password), kdfParams.Salt, kdfParams.N, kdfParams.R, kdfParams.P, kdfParams.Dklen)
	if err != nil {
		return nil, err
	}

	// Decrypt the private key. GCM's Open function handles authentication.
	// If the password is wrong, the derived key will be wrong, and authentication will fail.
	privKeyBytes, err := pre.GCMDecrypt(key.Crypto.CipherText, derivedKey, nil)
	if err != nil {
		return nil, ErrInvalidPassword
	}

	// Reconstruct the ecdsa.PrivateKey
	crv := curve.CurveGet(key.CurveName)
	if crv == nil {
		return nil, fmt.Errorf("unsupported curve: %s", key.CurveName)
	}
	return utils.PrivateKeyFromBytes(crv, privKeyBytes)
}

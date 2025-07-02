package pre

import (
	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/izouxv/goRecrypt/utils"
)

func EncryptMessageByAESKey(message []byte, keyBytes []byte) (cipherText []byte, err error) {
	// Use AES-GCM algorithm to encrypt, key is the first 32 bytes of the hash.
	cipherText, err = GCMEncrypt(message, keyBytes[:AES256KeySize], nil)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

// Encrypt encrypts a message using AES-GCM and Proxy Re-Encryption.
func Encrypt(message []byte, pubKey *ecdsa.PublicKey) (cipherText []byte, capsule *Capsule, err error) {
	capsule, keyBytes, err := EncryptKeyGen(pubKey)
	if err != nil {
		return nil, nil, err
	}
	// Use AES-GCM algorithm to encrypt, key is the first 32 bytes of the hash.
	cipherText, err = GCMEncrypt(message, keyBytes[:AES256KeySize], nil)
	if err != nil {
		return nil, nil, err
	}
	return cipherText, capsule, nil
}

func EncryptByBytes(CURVE elliptic.Curve, message []byte, pubKeyBytes []byte) (cipherText []byte, capsule *Capsule, err error) {
	key, err := utils.PublicKeyFromBytes(CURVE, pubKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	return Encrypt(message, key)
}

// EncryptFile encrypts a file.
func EncryptFile(inputFile, outPutFile string, pubKey *ecdsa.PublicKey) (capsule *Capsule, err error) {
	capsule, keyBytes, err := EncryptKeyGen(pubKey)
	if err != nil {
		return nil, err
	}
	// Use AES-OFB algorithm to encrypt, key is the first 32 bytes of the hash.
	err = OFBFileEncrypt(keyBytes[:AES256KeySize], inputFile, outPutFile)
	if err != nil {
		return nil, err
	}
	return capsule, nil
}

// EncryptFileByBytes encrypts a file using a public key provided as bytes.
func EncryptFileByBytes(CURVE elliptic.Curve, inputFile, outPutFile string, pubKeyBytes []byte) (capsule *Capsule, err error) {
	key, err := utils.PublicKeyFromBytes(CURVE, pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return EncryptFile(inputFile, outPutFile, key)
}

// Decrypt recreates the AES key and then decrypts the ciphertext.
func Decrypt(bPriKey *ecdsa.PrivateKey, capsule *Capsule, pubX *ecdsa.PublicKey, cipherText []byte) (plainText []byte, err error) {
	keyBytes, err := DecryptKeyGen(bPriKey, capsule, pubX)
	if err != nil {
		return nil, err
	}
	// Recreate AES key = G((E' * V')^d)
	// Use AES-GCM to decrypt, key is the first 32 bytes of the hash.
	plainText, err = GCMDecrypt(cipherText, keyBytes[:AES256KeySize], nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func DecryptByBytes(bPriKeyBytes []byte, capsule *Capsule, pubXBytes []byte, cipherText []byte) (plainText []byte, err error) {
	bPriKey, err := utils.PrivateKeyFromBytes(capsule.Curve(), bPriKeyBytes)
	if err != nil {
		return nil, err
	}
	pubX, err := utils.PublicKeyFromBytes(capsule.Curve(), pubXBytes)
	if err != nil {
		return nil, err
	}
	return Decrypt(bPriKey, capsule, pubX, cipherText)
}

// DecryptFile decrypts a file.
func DecryptFile(inputFile, outPutFile string, bPriKey *ecdsa.PrivateKey, capsule *Capsule, pubX *ecdsa.PublicKey) (err error) {
	keyBytes, err := DecryptKeyGen(bPriKey, capsule, pubX)
	if err != nil {
		return err
	}
	// Use AES-OFB to decrypt, key is the first 32 bytes of the hash.
	err = OFBFileDecrypt(keyBytes[:AES256KeySize], inputFile, outPutFile)
	if err != nil {
		return err
	}
	return nil
}

// DecryptFileByBytes decrypts a file using keys provided as bytes.
func DecryptFileByBytes(inputFile, outPutFile string, bPriKeyBytes []byte, capsule *Capsule, pubXBytes []byte) (err error) {
	bPriKey, err := utils.PrivateKeyFromBytes(capsule.Curve(), bPriKeyBytes)
	if err != nil {
		return err
	}
	pubX, err := utils.PublicKeyFromBytes(capsule.Curve(), pubXBytes)
	if err != nil {
		return err
	}
	return DecryptFile(inputFile, outPutFile, bPriKey, capsule, pubX)
}

// DecryptOnMyPriKey decrypts using the original recipient's private key.
func DecryptOnMyPriKey(aPriKey *ecdsa.PrivateKey, capsule *Capsule, cipherText []byte) (plainText []byte, err error) {
	keyBytes, err := RecreateAesKeyByMyPriKey(capsule, aPriKey)
	if err != nil {
		return nil, err
	}
	// Use AES-GCM algorithm to decrypt, key is the first 32 bytes of the hash.
	plainText, err = GCMDecrypt(cipherText, keyBytes[:AES256KeySize], nil)
	return plainText, err
}

func DecryptOnMyPriKeyByBytes(aPriKeyBytes []byte, capsule *Capsule, cipherText []byte) (plainText []byte, err error) {
	aPriKey, err := utils.PrivateKeyFromBytes(capsule.Curve(), aPriKeyBytes)
	if err != nil {
		return nil, err
	}
	return DecryptOnMyPriKey(aPriKey, capsule, cipherText)
}

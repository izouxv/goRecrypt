package pre

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

func GCMEncrypt(plaintext []byte, key []byte, additionalData []byte) (cipherText []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Prepend the nonce to the ciphertext.
	cipherText = aesgcm.Seal(nonce, nonce, plaintext, additionalData)
	return cipherText, nil
}

func GCMDecrypt(cipherText []byte, key []byte, additionalData []byte) (plainText []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, actualCipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	plainText, err = aesgcm.Open(nil, nonce, actualCipherText, additionalData)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func OFBFileEncrypt(key []byte, infileName string, encfileName string) (err error) {
	inFile, err := os.Open(infileName)
	if err != nil {
		return err
	}
	defer inFile.Close()
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	outFile, err := os.OpenFile(encfileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Prepend the IV to the file.
	if _, err := outFile.Write(iv); err != nil {
		return err
	}

	stream := cipher.NewOFB(block, iv)
	writer := &cipher.StreamWriter{S: stream, W: outFile}
	// Copy the input file to the output file, encrypting as we go.
	if _, err := io.Copy(writer, inFile); err != nil {
		return err
	}
	return nil
}

func OFBFileDecrypt(key []byte, encfileName string, decfileName string) (err error) {
	inFile, err := os.Open(encfileName)
	if err != nil {
		return err
	}
	defer inFile.Close()
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := inFile.Read(iv); err != nil {
		return err
	}

	outFile, err := os.OpenFile(decfileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()

	stream := cipher.NewOFB(block, iv)
	reader := &cipher.StreamReader{S: stream, R: inFile}
	// Copy the input file to the output file, decrypting as we go.
	if _, err = io.Copy(outFile, reader); err != nil {
		return err
	}
	return nil
}

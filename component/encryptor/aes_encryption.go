package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// EncryptChunk encrypts a chunk of data using AES-GCM
// and returns the nonce along with encrypted chunk with
// authentication tag appended.
func EncryptChunk(data []byte, key []byte) (cipherText []byte, nonce []byte, err error) {
	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// Create AES-GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// Generate a random nonce
	nonce = make([]byte, gcm.NonceSize())
	// Generate a random nonce for each chunk
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	cipherText = gcm.Seal(nil, nonce, data, nil)

	return cipherText, nonce, nil
}

// DecryptChunk decrypts a chunk of data using the provided nonce
// and key and returns the plain text data.
func DecryptChunk(cipherText []byte, nonce []byte, key []byte) (plainText []byte, err error) {
	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create AES-GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plainText, err = gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

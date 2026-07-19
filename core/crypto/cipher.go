package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const aesKeySize = 32 // AES-256

// Cipher encrypts/decrypts values (AES-256-GCM) and derives deterministic
// blind indexes (HMAC-SHA256) for equality lookups over encrypted data.
type Cipher struct {
	aead          cipher.AEAD
	blindIndexKey []byte
}

func NewCipher(encryptionKey, blindIndexKey []byte) (*Cipher, error) {
	if len(encryptionKey) != aesKeySize {
		return nil, fmt.Errorf("encryption key must be %d bytes, got %d", aesKeySize, len(encryptionKey))
	}
	if len(blindIndexKey) == 0 {
		return nil, errors.New("blind index key must not be empty")
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead, blindIndexKey: blindIndexKey}, nil
}

// NewCipherFromBase64 decodes standard-base64 keys and builds a Cipher.
func NewCipherFromBase64(encryptionKeyB64, blindIndexKeyB64 string) (*Cipher, error) {
	enc, err := base64.StdEncoding.DecodeString(encryptionKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode encryption key: %w", err)
	}
	bi, err := base64.StdEncoding.DecodeString(blindIndexKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode blind index key: %w", err)
	}
	return NewCipher(enc, bi)
}

// Encrypt returns base64(nonce || ciphertext).
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

func (c *Cipher) Decrypt(ciphertext string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	plaintext, err := c.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// BlindIndex returns a deterministic HMAC-SHA256 hex digest for equality lookups.
func (c *Cipher) BlindIndex(value string) string {
	mac := hmac.New(sha256.New, c.blindIndexKey)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

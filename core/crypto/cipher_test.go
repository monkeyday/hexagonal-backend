package crypto

import (
	"strings"
	"testing"
)

var (
	testEncKey  = []byte("12345678901234567890123456789012") // 32 bytes
	testBIKey   = []byte("blind-index-key-for-testing-only")
	testEncKey2 = []byte("abcdefghijklmnopqrstuvwxyz123456") // 32 bytes, different
)

func mustNewCipher(t *testing.T, encKey, biKey []byte) *Cipher {
	t.Helper()
	c, err := NewCipher(encKey, biKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
	}{
		{"empty string", ""},
		{"email address", "user@example.com"},
		{"unicode", "héllo@wörld.com"},
		{"long value", strings.Repeat("a", 1000)},
	}

	c := mustNewCipher(t, testEncKey, testBIKey)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := c.Encrypt(tc.plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			got, err := c.Decrypt(ct)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if got != tc.plaintext {
				t.Errorf("round-trip: got %q, want %q", got, tc.plaintext)
			}
		})
	}
}

func TestEncryptRandomNonce(t *testing.T) {
	c := mustNewCipher(t, testEncKey, testBIKey)
	plaintext := "same@example.com"

	ct1, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}
	ct2, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}

	if ct1 == ct2 {
		t.Error("two Encrypt calls on the same input produced identical ciphertext (nonce must be random)")
	}

	got1, err := c.Decrypt(ct1)
	if err != nil {
		t.Fatalf("Decrypt ct1: %v", err)
	}
	got2, err := c.Decrypt(ct2)
	if err != nil {
		t.Fatalf("Decrypt ct2: %v", err)
	}
	if got1 != plaintext || got2 != plaintext {
		t.Errorf("decrypted values: got %q and %q, want %q", got1, got2, plaintext)
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	c1 := mustNewCipher(t, testEncKey, testBIKey)
	c2 := mustNewCipher(t, testEncKey2, testBIKey)

	ct, err := c1.Encrypt("secret@example.com")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = c2.Decrypt(ct)
	if err == nil {
		t.Error("Decrypt with wrong key should have failed but succeeded")
	}
}

func TestBlindIndex(t *testing.T) {
	t.Run("deterministic for same input", func(t *testing.T) {
		c := mustNewCipher(t, testEncKey, testBIKey)
		bi1 := c.BlindIndex("user@example.com")
		bi2 := c.BlindIndex("user@example.com")
		if bi1 != bi2 {
			t.Errorf("BlindIndex not deterministic: %q != %q", bi1, bi2)
		}
	})

	t.Run("differs across inputs", func(t *testing.T) {
		c := mustNewCipher(t, testEncKey, testBIKey)
		bi1 := c.BlindIndex("user@example.com")
		bi2 := c.BlindIndex("other@example.com")
		if bi1 == bi2 {
			t.Error("BlindIndex should differ for different inputs")
		}
	})

	t.Run("stable across two instances with same blind index key", func(t *testing.T) {
		c1 := mustNewCipher(t, testEncKey, testBIKey)
		c2 := mustNewCipher(t, testEncKey2, testBIKey)
		input := "stable@example.com"
		if c1.BlindIndex(input) != c2.BlindIndex(input) {
			t.Error("BlindIndex should be identical when blind index key is the same, regardless of encryption key")
		}
	})
}

func TestNewCipherRejectsInvalidKeys(t *testing.T) {
	t.Run("encryption key too short", func(t *testing.T) {
		_, err := NewCipher([]byte("tooshort"), testBIKey)
		if err == nil {
			t.Error("expected error for short encryption key")
		}
	})

	t.Run("encryption key too long", func(t *testing.T) {
		_, err := NewCipher([]byte("this-key-is-way-too-long-to-be-valid-for-aes-256"), testBIKey)
		if err == nil {
			t.Error("expected error for long encryption key")
		}
	})

	t.Run("empty blind index key", func(t *testing.T) {
		_, err := NewCipher(testEncKey, []byte{})
		if err == nil {
			t.Error("expected error for empty blind index key")
		}
	})
}

func TestDecryptMalformedCiphertext(t *testing.T) {
	c := mustNewCipher(t, testEncKey, testBIKey)

	t.Run("invalid base64", func(t *testing.T) {
		_, err := c.Decrypt("not-valid-base64!!!")
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("ciphertext too short", func(t *testing.T) {
		// base64 of a few bytes — shorter than nonce size (12 bytes for GCM)
		_, err := c.Decrypt("dG9vc2hvcnQ=") // "tooshort" in base64
		if err == nil {
			t.Error("expected error for ciphertext shorter than nonce")
		}
	})
}

package secrets

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func newKEK(t *testing.T) []byte {
	t.Helper()
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return kek
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	kek := newKEK(t)
	plaintext := []byte(`{"refresh_token":"1//abcdef","client_secret":"GOCSPX-deadbeef"}`)

	blob, err := Encrypt(kek, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if blob.Version != EncVersionV1 {
		t.Fatalf("version: want %d, got %d", EncVersionV1, blob.Version)
	}
	if bytes.Contains(blob.Ciphertext, plaintext) {
		t.Fatal("ciphertext contains plaintext substring")
	}

	got, err := Decrypt(kek, blob)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: %q vs %q", got, plaintext)
	}
}

func TestDecryptFailsOnTamperedCiphertext(t *testing.T) {
	kek := newKEK(t)
	blob, err := Encrypt(kek, []byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	blob.Ciphertext[0] ^= 0x01

	if _, err := Decrypt(kek, blob); err == nil {
		t.Fatal("expected decrypt to fail on tampered ciphertext")
	}
}

func TestDecryptFailsOnTamperedWrappedDEK(t *testing.T) {
	kek := newKEK(t)
	blob, err := Encrypt(kek, []byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	blob.WrappedDEK[0] ^= 0x01

	if _, err := Decrypt(kek, blob); err == nil {
		t.Fatal("expected decrypt to fail on tampered wrapped DEK")
	}
}

func TestDecryptFailsOnWrongKEK(t *testing.T) {
	kek := newKEK(t)
	other := newKEK(t)

	blob, err := Encrypt(kek, []byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := Decrypt(other, blob); err == nil {
		t.Fatal("expected decrypt to fail with wrong KEK")
	}
}

func TestEncryptRejectsBadKEKSize(t *testing.T) {
	if _, err := Encrypt(make([]byte, 16), []byte("x")); err == nil {
		t.Fatal("expected error for 16-byte KEK")
	}
}

func TestEncryptUniqueDEKsAndNonces(t *testing.T) {
	kek := newKEK(t)
	a, err := Encrypt(kek, []byte("same payload"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(kek, []byte("same payload"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Nonce, b.Nonce) {
		t.Fatal("payload nonces collided")
	}
	if bytes.Equal(a.DEKNonce, b.DEKNonce) {
		t.Fatal("dek nonces collided")
	}
	if bytes.Equal(a.WrappedDEK, b.WrappedDEK) {
		t.Fatal("wrapped DEKs collided — DEKs are supposed to be fresh per call")
	}
	if bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("ciphertexts collided")
	}
}

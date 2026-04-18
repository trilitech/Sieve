// Package secrets implements envelope encryption for stored credentials.
//
// Sieve holds the real credentials for upstream services (OAuth refresh
// tokens, API keys, client secrets) in connections.config. Without
// encryption, anyone with the SQLite file — through theft, backup leak,
// snapshot, or SQLi read — gets full credential compromise.
//
// This package centralizes the crypto: a passphrase-derived KEK held only
// in process memory, per-record DEKs wrapped under the KEK, AES-256-GCM
// for both. The KEK never lands on disk — stop the process and the only
// thing left is ciphertext.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// EncVersionV1 tags records encrypted with the v1 algorithm
// (AES-256-GCM ciphertext, AES-256-GCM-wrapped 32-byte DEK, 12-byte nonces).
const EncVersionV1 = 1

// dekSize is the size of a Data Encryption Key in bytes.
const dekSize = 32

// nonceSize is the GCM nonce size in bytes.
const nonceSize = 12

// EncryptedBlob carries an encrypted payload and the wrapped DEK that
// decrypts it. The five fields land in five SQLite columns.
type EncryptedBlob struct {
	Ciphertext []byte
	Nonce      []byte
	WrappedDEK []byte
	DEKNonce   []byte
	Version    int
}

// Encrypt generates a fresh DEK, encrypts plaintext with it under
// AES-256-GCM, and wraps the DEK under kek (also AES-256-GCM).
//
// kek must be exactly 32 bytes (AES-256). A new DEK is drawn for every
// call — we never reuse a DEK across records, so a single compromise
// stays scoped to one record and key rotation can re-wrap DEKs without
// touching ciphertext blobs.
func Encrypt(kek, plaintext []byte) (*EncryptedBlob, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("kek must be 32 bytes, got %d", len(kek))
	}

	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("generate dek: %w", err)
	}

	ciphertext, nonce, err := gcmSeal(dek, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt payload: %w", err)
	}

	wrappedDEK, dekNonce, err := gcmSeal(kek, dek)
	if err != nil {
		return nil, fmt.Errorf("wrap dek: %w", err)
	}

	return &EncryptedBlob{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		WrappedDEK: wrappedDEK,
		DEKNonce:   dekNonce,
		Version:    EncVersionV1,
	}, nil
}

// Decrypt unwraps the DEK with kek and decrypts the ciphertext.
// Returns an error on any GCM auth-tag mismatch (tampering or wrong key).
func Decrypt(kek []byte, blob *EncryptedBlob) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("kek must be 32 bytes, got %d", len(kek))
	}
	if blob.Version != EncVersionV1 {
		return nil, fmt.Errorf("unsupported encryption version %d", blob.Version)
	}

	dek, err := gcmOpen(kek, blob.WrappedDEK, blob.DEKNonce)
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}

	plaintext, err := gcmOpen(dek, blob.Ciphertext, blob.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}

	return plaintext, nil
}

// gcmSeal encrypts plaintext under key with a fresh random nonce.
func gcmSeal(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// gcmOpen decrypts ciphertext under key with the supplied nonce.
func gcmOpen(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

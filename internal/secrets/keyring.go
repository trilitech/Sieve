package secrets

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// ErrKeyringNotLoaded is returned by callers when an operation needs
// credential decryption but no passphrase has been supplied.
var ErrKeyringNotLoaded = errors.New("keyring not loaded: passphrase required")

// ErrWrongPassphrase is returned by Load when the supplied passphrase
// fails the verifier sentinel — i.e. the derived KEK does not decrypt
// the on-disk check value.
var ErrWrongPassphrase = errors.New("wrong passphrase")

// ErrCryptoMetaMissing is returned by Load when no crypto_meta row exists.
// Setup must be called for first-run installations.
var ErrCryptoMetaMissing = errors.New("crypto_meta not initialized: run setup first")

// ErrCryptoMetaPresent is returned by Setup when a crypto_meta row already
// exists — refuse to overwrite an existing keyring on accident.
var ErrCryptoMetaPresent = errors.New("crypto_meta already initialized")

// kekCheckSentinel is the fixed plaintext encrypted under the KEK and stored
// as kek_check. On Load we re-derive the KEK from the passphrase and verify
// it decrypts to this exact value — that catches a wrong passphrase before
// any write happens. The value is arbitrary and constant; only its
// constancy matters.
var kekCheckSentinel = []byte("sieve-kek-verify")

// Argon2Params records the work factors used to derive a KEK. Stored as JSON
// alongside the salt so future tunings don't break old installs.
type Argon2Params struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory_kib"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_len"`
}

// DefaultArgon2Params is the standard work factor for new installs.
// time=3, memory=256 MiB, threads=4, keyLen=32 — tuned for ~1s on a
// modern desktop, well within tolerance for a once-per-startup operation.
var DefaultArgon2Params = Argon2Params{
	Time:    3,
	Memory:  256 * 1024,
	Threads: 4,
	KeyLen:  32,
}

// saltSize is the salt length in bytes for argon2id.
const saltSize = 16

// Keyring holds the in-memory KEK. The zero value is unloaded — IsLoaded
// returns false and KEK panics. Loaded() exposes a copy of the key for
// the envelope-encryption helpers.
type Keyring struct {
	kek []byte // 32 bytes when loaded; nil when not.
}

// IsLoaded reports whether the keyring currently holds a KEK.
func (k *Keyring) IsLoaded() bool {
	return k != nil && len(k.kek) == 32
}

// KEK returns the in-memory KEK. Panics if the keyring is not loaded —
// callers must check IsLoaded (or rely on ErrKeyringNotLoaded surfaced
// by services) before reaching for the bytes.
func (k *Keyring) KEK() []byte {
	if !k.IsLoaded() {
		panic("secrets.Keyring: KEK accessed when not loaded")
	}
	return k.kek
}

// Lock zeroes the KEK in memory and clears the loaded flag. After Lock,
// IsLoaded returns false and any operation that needs decryption fails
// with ErrKeyringNotLoaded.
func (k *Keyring) Lock() {
	for i := range k.kek {
		k.kek[i] = 0
	}
	k.kek = nil
}

// Load derives a KEK from the passphrase, verifies it against the on-disk
// sentinel, and arms the keyring. Returns ErrWrongPassphrase on verifier
// mismatch, ErrCryptoMetaMissing if Setup hasn't been run.
func (k *Keyring) Load(db *sql.DB, passphrase []byte) error {
	salt, params, kekCheck, err := loadCryptoMeta(db)
	if err != nil {
		return err
	}

	kek := deriveKEK(passphrase, salt, params)

	if err := verifyKEK(kek, kekCheck); err != nil {
		// Zero the bad KEK before returning — defense in depth so a
		// wrong-passphrase derived key isn't left lying in the heap
		// for the GC to clean up later.
		for i := range kek {
			kek[i] = 0
		}
		return err
	}

	k.kek = kek
	return nil
}

// Setup performs first-run initialization: generates a random salt, derives
// the KEK, encrypts the verifier sentinel, and persists crypto_meta. After
// Setup the keyring is loaded and ready for use.
//
// Setup refuses to run if a crypto_meta row already exists — that would
// silently orphan every existing ciphertext blob. Use Rotate to change
// the passphrase.
func (k *Keyring) Setup(db *sql.DB, passphrase []byte) error {
	exists, err := cryptoMetaExists(db)
	if err != nil {
		return err
	}
	if exists {
		return ErrCryptoMetaPresent
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	params := DefaultArgon2Params
	kek := deriveKEK(passphrase, salt, params)

	kekCheck, err := buildKEKCheck(kek)
	if err != nil {
		return fmt.Errorf("build verifier: %w", err)
	}

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal params: %w", err)
	}

	if _, err := db.Exec(
		`INSERT INTO crypto_meta (id, argon2_salt, argon2_params, kek_check) VALUES (1, ?, ?, ?)`,
		salt, string(paramsJSON), kekCheck,
	); err != nil {
		return fmt.Errorf("insert crypto_meta: %w", err)
	}

	k.kek = kek
	return nil
}

// Rotate re-derives the KEK from a new passphrase and rewraps every
// per-record DEK (currently in connections.dek_wrapped) under the new KEK.
// Crypto_meta is updated last; if any step fails, the call returns an
// error and the on-disk state is unchanged because the writes are inside
// a single transaction.
//
// Ciphertext blobs themselves are untouched — only the wrapped DEKs need
// to be re-wrapped under the new KEK.
func (k *Keyring) Rotate(db *sql.DB, oldPassphrase, newPassphrase []byte) error {
	salt, params, kekCheck, err := loadCryptoMeta(db)
	if err != nil {
		return err
	}

	oldKEK := deriveKEK(oldPassphrase, salt, params)
	defer zero(oldKEK)
	if err := verifyKEK(oldKEK, kekCheck); err != nil {
		return err
	}

	newSalt := make([]byte, saltSize)
	if _, err := rand.Read(newSalt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	newParams := DefaultArgon2Params
	newKEK := deriveKEK(newPassphrase, newSalt, newParams)

	tx, err := db.Begin()
	if err != nil {
		zero(newKEK)
		return fmt.Errorf("begin rotate tx: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT id, dek_wrapped, dek_nonce FROM connections`)
	if err != nil {
		zero(newKEK)
		return fmt.Errorf("scan connections: %w", err)
	}

	type rewrap struct {
		id            string
		newWrappedDEK []byte
		newDEKNonce   []byte
	}
	var rewraps []rewrap
	for rows.Next() {
		var id string
		var wrapped, nonce []byte
		if err := rows.Scan(&id, &wrapped, &nonce); err != nil {
			rows.Close()
			zero(newKEK)
			return fmt.Errorf("scan connection: %w", err)
		}
		dek, err := gcmOpen(oldKEK, wrapped, nonce)
		if err != nil {
			rows.Close()
			zero(newKEK)
			return fmt.Errorf("unwrap dek for %s: %w", id, err)
		}
		newWrapped, newNonce, err := gcmSeal(newKEK, dek)
		zero(dek)
		if err != nil {
			rows.Close()
			zero(newKEK)
			return fmt.Errorf("rewrap dek for %s: %w", id, err)
		}
		rewraps = append(rewraps, rewrap{id, newWrapped, newNonce})
	}
	rows.Close()

	for _, r := range rewraps {
		if _, err := tx.Exec(
			`UPDATE connections SET dek_wrapped = ?, dek_nonce = ? WHERE id = ?`,
			r.newWrappedDEK, r.newDEKNonce, r.id,
		); err != nil {
			zero(newKEK)
			return fmt.Errorf("update wrapped dek for %s: %w", r.id, err)
		}
	}

	newKEKCheck, err := buildKEKCheck(newKEK)
	if err != nil {
		zero(newKEK)
		return fmt.Errorf("build verifier: %w", err)
	}
	paramsJSON, err := json.Marshal(newParams)
	if err != nil {
		zero(newKEK)
		return fmt.Errorf("marshal params: %w", err)
	}
	if _, err := tx.Exec(
		`UPDATE crypto_meta SET argon2_salt = ?, argon2_params = ?, kek_check = ? WHERE id = 1`,
		newSalt, string(paramsJSON), newKEKCheck,
	); err != nil {
		zero(newKEK)
		return fmt.Errorf("update crypto_meta: %w", err)
	}

	if err := tx.Commit(); err != nil {
		zero(newKEK)
		return fmt.Errorf("commit rotate: %w", err)
	}

	// Rotate the in-memory KEK to the new value.
	zero(k.kek)
	k.kek = newKEK
	return nil
}

func loadCryptoMeta(db *sql.DB) (salt []byte, params Argon2Params, kekCheck []byte, err error) {
	var paramsJSON string
	row := db.QueryRow(`SELECT argon2_salt, argon2_params, kek_check FROM crypto_meta WHERE id = 1`)
	if scanErr := row.Scan(&salt, &paramsJSON, &kekCheck); scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, params, nil, ErrCryptoMetaMissing
		}
		return nil, params, nil, fmt.Errorf("read crypto_meta: %w", scanErr)
	}
	if jsonErr := json.Unmarshal([]byte(paramsJSON), &params); jsonErr != nil {
		return nil, params, nil, fmt.Errorf("parse argon2 params: %w", jsonErr)
	}
	return salt, params, kekCheck, nil
}

func cryptoMetaExists(db *sql.DB) (bool, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM crypto_meta WHERE id = 1`).Scan(&n); err != nil {
		return false, fmt.Errorf("count crypto_meta: %w", err)
	}
	return n > 0, nil
}

func deriveKEK(passphrase, salt []byte, p Argon2Params) []byte {
	return argon2.IDKey(passphrase, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
}

// buildKEKCheck encrypts the fixed sentinel under kek and returns
// nonce || ciphertext as a single blob.
func buildKEKCheck(kek []byte) ([]byte, error) {
	ct, nonce, err := gcmSeal(kek, kekCheckSentinel)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// verifyKEK decrypts the on-disk kek_check blob with the supplied KEK and
// confirms it matches the sentinel.
func verifyKEK(kek, kekCheck []byte) error {
	if len(kekCheck) < nonceSize {
		return fmt.Errorf("kek_check truncated")
	}
	nonce := kekCheck[:nonceSize]
	ct := kekCheck[nonceSize:]
	pt, err := gcmOpen(kek, ct, nonce)
	if err != nil {
		return ErrWrongPassphrase
	}
	if subtle.ConstantTimeCompare(pt, kekCheckSentinel) != 1 {
		return ErrWrongPassphrase
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

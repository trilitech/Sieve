// Package operator stores and verifies Sieve's single shared admin credential
// (the operator credential introduced by
// The credential is distinct from the keyring passphrase and is held
// as an Argon2id verifier — salt + memory-hard derived key — rather than as
// an encrypted secret. Preimage resistance is the protection; there
// is no decrypt operation, only verification.
// First-run intake mirrors the keyring's TTY / SIEVE_OPERATOR_CREDENTIAL_FILE
// / FD3 (systemd LoadCredential) idiom. The display name captured at intake
// becomes the audit identity recorded on every operator mutation.
package operator

// Package operator stores and verifies Sieve's single shared admin
// credential — the credential a human operator types to log into the web
// admin UI on port 19816. It is distinct from the keyring passphrase
// (which guards connection-config encryption) and is held as an Argon2id
// verifier — salt + memory-hard derived key — rather than as an
// encrypted secret: preimage resistance is the protection; there is no
// decrypt operation, only verification.
//
// First-run intake mirrors the keyring's TTY / SIEVE_OPERATOR_CREDENTIAL_FILE
// / FD3 (systemd LoadCredential) idiom. The display name captured at intake
// becomes the audit identity recorded on every operator mutation.
package operator

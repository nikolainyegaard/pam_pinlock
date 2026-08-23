#ifndef PINLOCK_RECORD_H
#define PINLOCK_RECORD_H

#include <stddef.h>

// PIN record storage shared by the PAM module and pinlockctl.
// The record type is detected from file content, so different backends
// can coexist per file without configuration.

typedef enum {
    PINLOCK_RECORD_ARGON2,
    PINLOCK_RECORD_TPM2,
    PINLOCK_RECORD_UNKNOWN,
} pinlock_record_type_t;

// First line of a TPM-backed record file. The v1 sso variant seals the
// account password directly. The v2 sso variant seals a random key and
// stores the password encrypted under it, plus a password-wrapped copy
// of the key, so a password change can rewrap the record without the
// PIN or the TPM.
#define PINLOCK_TPM2_HEADER "pinlock-tpm2 v1"
#define PINLOCK_TPM2_HEADER_SSO "pinlock-tpm2 v1 sso"
#define PINLOCK_TPM2_HEADER_V2_SSO "pinlock-tpm2 v2 sso"

#define PINLOCK_VERIFY_OK           0
#define PINLOCK_VERIFY_FAIL         1
#define PINLOCK_VERIFY_LOCKOUT      2
#define PINLOCK_VERIFY_UNREADABLE (-1)
#define PINLOCK_VERIFY_UNAVAILABLE (-2)

// Detect the record type from the first line of a PIN file.
pinlock_record_type_t pinlock_record_type(const char *first_line);

// Detect the record type stored at path without verifying anything.
// Returns PINLOCK_RECORD_UNKNOWN if the file cannot be read.
pinlock_record_type_t pinlock_record_type_of_file(const char *path);

// Verify a PIN against the record stored at path. tpm2_tcti selects the
// TPM connection for TPM records (NULL or empty for the library default).
// Returns PINLOCK_VERIFY_OK; PINLOCK_VERIFY_FAIL for a wrong PIN or
// unrecognized record; PINLOCK_VERIFY_LOCKOUT if the TPM is in dictionary
// attack lockout; PINLOCK_VERIFY_UNREADABLE if the record cannot be read;
// PINLOCK_VERIFY_UNAVAILABLE if the record needs a TPM that cannot be
// used (unreachable, cleared since enrollment, or support not built in).
// On success with a record carrying a sealed account password, stores it
// (heap-allocated, NUL-terminated) in *sso_secret_out if non-NULL; the
// caller must wipe and free it.
int pinlock_verify_pin(const char *path, const char *pin, const char *tpm2_tcti, char **sso_secret_out);

// Create an argon2id record string for a new PIN. On success stores a
// heap-allocated encoded string in *encoded_out (caller frees) and
// returns 0. Returns -1 on RNG failure, -2 on allocation failure, -3 on
// hashing failure with the argon2 error code stored in *argon2_rc.
int pinlock_record_create_argon2(const char *pin, char **encoded_out, int *argon2_rc);

// Base64 (standard alphabet, '=' padding). encode returns a heap string
// or NULL; decode returns 0 and the byte count in *outlen, -1 on bad
// input or overflow of cap.
char *pinlock_b64_encode(const unsigned char *in, size_t len);
int pinlock_b64_decode(const char *in, size_t inlen, unsigned char *out, size_t cap, size_t *outlen);

#ifdef HAVE_TPM2
// Crypto lines of a v2 sso record (key: the 32-byte TPM-sealed key).
// pinlock_sso_wrap produces the salt, key-wrap, and password blob lines
// as heap base64 strings (caller frees all three). Returns 0 or -1.
int pinlock_sso_wrap(const unsigned char *key, const char *password,
                     char **salt_b64, char **kwrap_b64, char **pwblob_b64);

// Recover the account password from a v2 sso password blob line using
// the unsealed key. On success stores a heap NUL-terminated string in
// *password_out (caller wipes and frees). Returns 0 or -1.
int pinlock_sso_unwrap_password(const unsigned char *key, const char *pwblob_b64,
                                char **password_out);

// Rewrap a v2 sso record for a changed account password, without the
// PIN or the TPM. Returns 0 on success, 1 if old_password does not
// match the record, 2 if the record is not a v2 sso record, -1 on
// read/write errors.
int pinlock_record_update_password(const char *path, const char *old_password,
                                   const char *new_password);
#endif

#endif

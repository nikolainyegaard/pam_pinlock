#ifndef PINLOCK_RECORD_H
#define PINLOCK_RECORD_H

// PIN record storage shared by the PAM module and pinlockctl.
// The record type is detected from file content, so different backends
// can coexist per file without configuration.

typedef enum {
    PINLOCK_RECORD_ARGON2,
    PINLOCK_RECORD_TPM2,
    PINLOCK_RECORD_UNKNOWN,
} pinlock_record_type_t;

// First line of a TPM-backed record file.
#define PINLOCK_TPM2_HEADER "pinlock-tpm2 v1"

#define PINLOCK_VERIFY_OK           0
#define PINLOCK_VERIFY_FAIL         1
#define PINLOCK_VERIFY_LOCKOUT      2
#define PINLOCK_VERIFY_UNREADABLE (-1)
#define PINLOCK_VERIFY_UNAVAILABLE (-2)

// Detect the record type from the first line of a PIN file.
pinlock_record_type_t pinlock_record_type(const char *first_line);

// Verify a PIN against the record stored at path. tpm2_tcti selects the
// TPM connection for TPM records (NULL or empty for the library default).
// Returns PINLOCK_VERIFY_OK; PINLOCK_VERIFY_FAIL for a wrong PIN or
// unrecognized record; PINLOCK_VERIFY_LOCKOUT if the TPM is in dictionary
// attack lockout; PINLOCK_VERIFY_UNREADABLE if the record cannot be read;
// PINLOCK_VERIFY_UNAVAILABLE if the record needs a TPM that cannot be
// used (unreachable, cleared since enrollment, or support not built in).
int pinlock_verify_pin(const char *path, const char *pin, const char *tpm2_tcti);

// Create an argon2id record string for a new PIN. On success stores a
// heap-allocated encoded string in *encoded_out (caller frees) and
// returns 0. Returns -1 on RNG failure, -2 on allocation failure, -3 on
// hashing failure with the argon2 error code stored in *argon2_rc.
int pinlock_record_create_argon2(const char *pin, char **encoded_out, int *argon2_rc);

#endif

#ifndef PINLOCK_RECORD_H
#define PINLOCK_RECORD_H

// PIN record storage shared by the PAM module and pinlockctl.
// The record type is detected from file content, so different backends
// can coexist per file without configuration.

typedef enum {
    PINLOCK_RECORD_ARGON2,
    PINLOCK_RECORD_UNKNOWN,
} pinlock_record_type_t;

#define PINLOCK_VERIFY_OK          0
#define PINLOCK_VERIFY_FAIL        1
#define PINLOCK_VERIFY_UNREADABLE (-1)

// Detect the record type from the first line of a PIN file.
pinlock_record_type_t pinlock_record_type(const char *first_line);

// Verify a PIN against the record stored at path.
// Returns PINLOCK_VERIFY_OK, PINLOCK_VERIFY_FAIL for a wrong PIN or
// unrecognized record, or PINLOCK_VERIFY_UNREADABLE if the record
// cannot be read.
int pinlock_verify_pin(const char *path, const char *pin);

// Create an argon2id record string for a new PIN. On success stores a
// heap-allocated encoded string in *encoded_out (caller frees) and
// returns 0. Returns -1 on RNG failure, -2 on allocation failure, -3 on
// hashing failure with the argon2 error code stored in *argon2_rc.
int pinlock_record_create_argon2(const char *pin, char **encoded_out, int *argon2_rc);

#endif

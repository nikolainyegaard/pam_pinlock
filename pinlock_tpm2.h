#ifndef PINLOCK_TPM2_H
#define PINLOCK_TPM2_H

// TPM 2.0 sealed-PIN backend. Compiled only when built with TPM2=1.
//
// Enrollment seals a random secret in a TPM object protected by the
// TPM's dictionary attack lockout, with the PIN as its auth value.
// Verification loads the sealed object and attempts TPM2_Unseal over
// a salted, parameter-encrypted HMAC session, so the PIN never leaves
// the host or crosses the TPM bus in plaintext. There is no hash on
// disk to attack offline; the record is useless without the physical
// TPM that created it.

// A TPM PIN may not exceed the auth value limit of the sealed object.
#define PINLOCK_TPM2_MAX_PIN 32

#include <stdint.h>

// Probe for a usable TPM. Returns 1 if available, 0 if not.
// tcti_conf selects the TPM connection (NULL or empty for the library
// default, typically /dev/tpmrm0).
int pinlock_tpm2_available(const char *tcti_conf);

// Dictionary attack state of the TPM. The counter and lockout are
// chip-global, shared with every other user of this TPM.
typedef struct {
    int in_lockout;
    int lockout_auth_set;       // lockout hierarchy has an auth value; if
                                // it is unknown (set by a previous OS),
                                // the counter cannot be cleared manually
    uint32_t lockout_counter;   // failed auth attempts currently counted
    uint32_t max_auth_fail;     // failures that trigger lockout
    uint32_t lockout_interval;  // seconds until the counter decrements
    uint32_t lockout_recovery;  // seconds until an active lockout clears
} pinlock_tpm2_da_info_t;

// Read the TPM's dictionary attack state. Returns 0 on success, -1 if
// the TPM is unavailable.
int pinlock_tpm2_da_info(const char *tcti_conf, pinlock_tpm2_da_info_t *info);

// Seal a new PIN into a TPM record. On success stores heap-allocated
// record text (header line plus base64 blob lines, newline-terminated)
// in *record_out and returns 0. Returns -1 on any failure.
// sso_password may be NULL: the sealed payload is then a random secret
// and unsealing only proves the PIN. When given (at most
// PINLOCK_TPM2_MAX_SSO bytes), the payload is that password and the
// record is marked so verification can return it, letting a PIN
// sign-in unlock password-derived secrets such as KWallet.
int pinlock_tpm2_seal(const char *tcti_conf, const char *pin, const char *sso_password, char **record_out);

#define PINLOCK_TPM2_MAX_SSO 128

// Verify a PIN against TPM record text. Returns the PINLOCK_VERIFY_*
// codes from pinlock_record.h: OK, FAIL (wrong PIN), LOCKOUT (TPM is
// in dictionary attack lockout), or UNAVAILABLE (TPM unreachable, or
// the record does not belong to this TPM). On success with a record
// that carries a sealed password, stores it (heap-allocated,
// NUL-terminated) in *sso_secret_out if non-NULL; the caller must wipe
// and free it.
int pinlock_tpm2_verify(const char *tcti_conf, const char *record_text, const char *pin, char **sso_secret_out);

#endif

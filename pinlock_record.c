#define _GNU_SOURCE
#include "pinlock_record.h"
#ifdef HAVE_TPM2
#include "pinlock_tpm2.h"
#endif

#include <argon2.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Records are small; anything larger than this is not one of ours.
#define RECORD_MAX_SIZE 16384

// Read whole record file, NUL-terminated
static int read_record_file(const char *path, char **out) {
    *out = NULL;
#ifdef O_NOFOLLOW
    int fd = open(path, O_RDONLY|O_NOFOLLOW);
#else
    int fd = open(path, O_RDONLY);
#endif
    if (fd < 0) return -1;
    char *buf = malloc(RECORD_MAX_SIZE + 1);
    if (!buf) { close(fd); return -1; }
    ssize_t total = 0;
    for (;;) {
        ssize_t n = read(fd, buf + total, (size_t)(RECORD_MAX_SIZE - total));
        if (n < 0) { close(fd); free(buf); return -1; }
        if (n == 0) break;
        total += n;
        if (total >= RECORD_MAX_SIZE) { close(fd); free(buf); return -1; }
    }
    close(fd);
    if (total == 0) { free(buf); return -1; }
    buf[total] = '\0';
    if (memchr(buf, '\0', (size_t)total)) { free(buf); return -1; }
    *out = buf;
    return 0;
}

pinlock_record_type_t pinlock_record_type(const char *first_line) {
    if (!first_line) return PINLOCK_RECORD_UNKNOWN;
    if (strncmp(first_line, "$argon2id$", 10) == 0) return PINLOCK_RECORD_ARGON2;
    if (strncmp(first_line, PINLOCK_TPM2_HEADER, strlen(PINLOCK_TPM2_HEADER)) == 0)
        return PINLOCK_RECORD_TPM2;
    return PINLOCK_RECORD_UNKNOWN;
}

pinlock_record_type_t pinlock_record_type_of_file(const char *path) {
    char first[256];
#ifdef O_NOFOLLOW
    int fd = open(path, O_RDONLY|O_NOFOLLOW);
#else
    int fd = open(path, O_RDONLY);
#endif
    if (fd < 0) return PINLOCK_RECORD_UNKNOWN;
    ssize_t n = read(fd, first, sizeof(first) - 1);
    close(fd);
    if (n <= 0) return PINLOCK_RECORD_UNKNOWN;
    first[n] = '\0';
    first[strcspn(first, "\r\n")] = '\0';
    return pinlock_record_type(first);
}

int pinlock_verify_pin(const char *path, const char *pin, const char *tpm2_tcti) {
    char *text = NULL;
    if (read_record_file(path, &text) != 0 || !text) return PINLOCK_VERIFY_UNREADABLE;

    // First line, NUL-terminated for type detection and argon2
    char first[256];
    size_t flen = strcspn(text, "\r\n");
    if (flen >= sizeof(first)) flen = sizeof(first) - 1;
    memcpy(first, text, flen);
    first[flen] = '\0';

    int result;
    switch (pinlock_record_type(first)) {
    case PINLOCK_RECORD_ARGON2:
        result = argon2id_verify(first, pin, strlen(pin)) == ARGON2_OK
            ? PINLOCK_VERIFY_OK : PINLOCK_VERIFY_FAIL;
        break;
    case PINLOCK_RECORD_TPM2:
#ifdef HAVE_TPM2
        result = pinlock_tpm2_verify(tpm2_tcti, text, pin);
#else
        (void)tpm2_tcti;
        result = PINLOCK_VERIFY_UNAVAILABLE;
#endif
        break;
    default:
        result = PINLOCK_VERIFY_FAIL;
        break;
    }

    free(text);
    return result;
}

int pinlock_record_create_argon2(const char *pin, char **encoded_out, int *argon2_rc) {
    *encoded_out = NULL;
    if (argon2_rc) *argon2_rc = 0;

    unsigned char salt[16];
    int rnd = open("/dev/urandom", O_RDONLY);
    if (rnd < 0) return -1;
    ssize_t got = read(rnd, salt, sizeof(salt));
    close(rnd);
    if (got != (ssize_t)sizeof(salt)) return -1;

    unsigned long t_cost=3, m_cost=1u<<16, parallel=1;
    size_t enc_len = argon2_encodedlen(t_cost, m_cost, parallel, sizeof(salt), 32, Argon2_id);
    char *encoded = malloc(enc_len);
    if (!encoded) return -2;

    int rc = argon2id_hash_encoded((uint32_t)t_cost,(uint32_t)m_cost,(uint32_t)parallel,
                                   pin, strlen(pin), salt, sizeof(salt), 32, encoded, enc_len);
    if (rc != ARGON2_OK) {
        free(encoded);
        if (argon2_rc) *argon2_rc = rc;
        return -3;
    }

    *encoded_out = encoded;
    return 0;
}

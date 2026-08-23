#define _GNU_SOURCE
#include "pinlock_record.h"
#ifdef HAVE_TPM2
#include "pinlock_tpm2.h"
#endif

#include <argon2.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_TPM2
#include <openssl/evp.h>
#endif

// Records are small; anything larger than this is not one of ours.
#define RECORD_MAX_SIZE 16384

static void wipe(void *v, size_t n) {
#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2,25)
    explicit_bzero(v,n);
    return;
#endif
#endif
    volatile unsigned char *p=(volatile unsigned char*)v;
    while(n--) *p++=0;
}

/* ---------- base64 ---------- */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *pinlock_b64_encode(const unsigned char *in, size_t len) {
    size_t olen = 4 * ((len + 2) / 3);
    char *out = malloc(olen + 1);
    if (!out) return NULL;
    size_t i, o = 0;
    for (i = 0; i + 2 < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i+1] << 8 | in[i+2];
        out[o++] = B64[v >> 18]; out[o++] = B64[(v >> 12) & 63];
        out[o++] = B64[(v >> 6) & 63]; out[o++] = B64[v & 63];
    }
    if (i < len) {
        uint32_t v = (uint32_t)in[i] << 16;
        int rem = (int)(len - i);
        if (rem == 2) v |= (uint32_t)in[i+1] << 8;
        out[o++] = B64[v >> 18]; out[o++] = B64[(v >> 12) & 63];
        out[o++] = rem == 2 ? B64[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return out;
}

int pinlock_b64_decode(const char *in, size_t inlen, unsigned char *out, size_t cap, size_t *outlen) {
    size_t o = 0;
    uint32_t v = 0;
    int bits = 0;
    for (size_t i = 0; i < inlen; i++) {
        if (in[i] == '=') break;
        const char *p = strchr(B64, in[i]);
        if (!p || !in[i]) return -1;
        v = v << 6 | (uint32_t)(p - B64);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (unsigned char)(v >> bits);
        }
    }
    *outlen = o;
    return 0;
}

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
    if (strncmp(first_line, "pinlock-tpm2 ", 13) == 0) return PINLOCK_RECORD_TPM2;
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

int pinlock_verify_pin(const char *path, const char *pin, const char *tpm2_tcti, char **sso_secret_out) {
    if (sso_secret_out) *sso_secret_out = NULL;
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
        result = pinlock_tpm2_verify(tpm2_tcti, text, pin, sso_secret_out);
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

#ifdef HAVE_TPM2

/* ---------- v2 sso wrapping ----------
 *
 * The TPM seals a random 32-byte key. The record additionally stores
 * the account password encrypted under that key (pwblob), and the key
 * encrypted under a key derived from the password (kwrap). The kwrap
 * copy is deliberately circular: it protects nothing beyond the
 * password that unlocks it, but it lets a password change rewrap the
 * record given only the old password, with no PIN and no TPM.
 */

#define SSO_SALT_LEN 16
#define SSO_KEY_LEN 32
#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN 16
#define GCM_OVERHEAD (GCM_NONCE_LEN + GCM_TAG_LEN)

// out = nonce || ciphertext || tag
static int gcm_seal(const unsigned char *key, const unsigned char *pt, size_t ptlen,
                    unsigned char *out, size_t *outlen) {
    if (getrandom(out, GCM_NONCE_LEN, 0) != GCM_NONCE_LEN) return -1;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    int len = 0, fin = 0, ok = -1;
    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, out) == 1
            && EVP_EncryptUpdate(c, out + GCM_NONCE_LEN, &len, pt, (int)ptlen) == 1
            && EVP_EncryptFinal_ex(c, out + GCM_NONCE_LEN + len, &fin) == 1
            && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN,
                                   out + GCM_NONCE_LEN + len + fin) == 1) {
        *outlen = GCM_NONCE_LEN + (size_t)(len + fin) + GCM_TAG_LEN;
        ok = 0;
    }
    EVP_CIPHER_CTX_free(c);
    return ok;
}

// pt must have room for bloblen - GCM_OVERHEAD bytes. Fails on a bad
// tag, so a successful open authenticates the key.
static int gcm_open(const unsigned char *key, const unsigned char *blob, size_t bloblen,
                    unsigned char *pt, size_t *ptlen) {
    if (bloblen < GCM_OVERHEAD) return -1;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    int len = 0, fin = 0, ok = -1;
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, blob) == 1
            && EVP_DecryptUpdate(c, pt, &len, blob + GCM_NONCE_LEN,
                                 (int)(bloblen - GCM_OVERHEAD)) == 1
            && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                                   (void *)(blob + bloblen - GCM_TAG_LEN)) == 1
            && EVP_DecryptFinal_ex(c, pt + len, &fin) == 1) {
        *ptlen = (size_t)(len + fin);
        ok = 0;
    }
    EVP_CIPHER_CTX_free(c);
    return ok;
}

// Same argon2id cost as the PIN records; this key only ever wraps the
// key that decrypts the password the attacker would be guessing.
static int kdf_password(const char *password, const unsigned char *salt, unsigned char *key) {
    return argon2id_hash_raw(3, 1u<<16, 1, password, strlen(password),
                             salt, SSO_SALT_LEN, key, SSO_KEY_LEN) == ARGON2_OK ? 0 : -1;
}

int pinlock_sso_wrap(const unsigned char *key, const char *password,
                     char **salt_b64, char **kwrap_b64, char **pwblob_b64) {
    *salt_b64 = *kwrap_b64 = *pwblob_b64 = NULL;
    size_t pwlen = strlen(password);
    if (pwlen == 0 || pwlen > PINLOCK_TPM2_MAX_SSO) return -1;

    unsigned char salt[SSO_SALT_LEN], wrapkey[SSO_KEY_LEN];
    unsigned char kwrap[SSO_KEY_LEN + GCM_OVERHEAD];
    unsigned char pwblob[PINLOCK_TPM2_MAX_SSO + GCM_OVERHEAD];
    size_t kwlen, pblen;
    int ret = -1;

    if (getrandom(salt, sizeof(salt), 0) != (ssize_t)sizeof(salt)) return -1;
    if (kdf_password(password, salt, wrapkey) != 0) return -1;
    if (gcm_seal(wrapkey, key, SSO_KEY_LEN, kwrap, &kwlen) == 0
            && gcm_seal(key, (const unsigned char *)password, pwlen, pwblob, &pblen) == 0) {
        *salt_b64 = pinlock_b64_encode(salt, sizeof(salt));
        *kwrap_b64 = pinlock_b64_encode(kwrap, kwlen);
        *pwblob_b64 = pinlock_b64_encode(pwblob, pblen);
        if (*salt_b64 && *kwrap_b64 && *pwblob_b64) {
            ret = 0;
        } else {
            free(*salt_b64); free(*kwrap_b64); free(*pwblob_b64);
            *salt_b64 = *kwrap_b64 = *pwblob_b64 = NULL;
        }
    }
    wipe(wrapkey, sizeof(wrapkey));
    wipe(pwblob, sizeof(pwblob));
    return ret;
}

int pinlock_sso_unwrap_password(const unsigned char *key, const char *pwblob_b64,
                                char **password_out) {
    *password_out = NULL;
    unsigned char blob[PINLOCK_TPM2_MAX_SSO + GCM_OVERHEAD];
    unsigned char pt[PINLOCK_TPM2_MAX_SSO];
    size_t bloblen, ptlen;
    if (pinlock_b64_decode(pwblob_b64, strlen(pwblob_b64), blob, sizeof(blob), &bloblen) != 0)
        return -1;
    if (gcm_open(key, blob, bloblen, pt, &ptlen) != 0) return -1;
    char *out = malloc(ptlen + 1);
    if (out) {
        memcpy(out, pt, ptlen);
        out[ptlen] = '\0';
        *password_out = out;
    }
    wipe(pt, sizeof(pt));
    return out ? 0 : -1;
}

int pinlock_record_update_password(const char *path, const char *old_password,
                                   const char *new_password) {
    size_t newlen = strlen(new_password);
    if (newlen == 0 || newlen > PINLOCK_TPM2_MAX_SSO) return -1;

    char *text = NULL;
    if (read_record_file(path, &text) != 0 || !text) return -1;

    // Six lines: header, pub, priv, salt, kwrap, pwblob.
    char *lines[6];
    char *p = text;
    int nlines = 0;
    while (nlines < 6 && *p) {
        lines[nlines++] = p;
        char *nl = strchr(p, '\n');
        if (!nl) break;
        *nl = '\0';
        p = nl + 1;
    }
    int ret = -1;
    char *salt64 = NULL, *kwrap64 = NULL, *pwblob64 = NULL;
    unsigned char salt[SSO_SALT_LEN], wrapkey[SSO_KEY_LEN];
    unsigned char kwrap[SSO_KEY_LEN + GCM_OVERHEAD + 4];
    unsigned char key[SSO_KEY_LEN + GCM_OVERHEAD];
    size_t saltlen, kwlen, keylen;

    if (nlines < 6 || strcmp(lines[0], PINLOCK_TPM2_HEADER_V2_SSO) != 0) {
        ret = 2;
        goto out;
    }
    if (pinlock_b64_decode(lines[3], strlen(lines[3]), salt, sizeof(salt), &saltlen) != 0
            || saltlen != SSO_SALT_LEN
            || pinlock_b64_decode(lines[4], strlen(lines[4]), kwrap, sizeof(kwrap), &kwlen) != 0)
        goto out;
    if (kdf_password(old_password, salt, wrapkey) != 0) goto out;
    if (gcm_open(wrapkey, kwrap, kwlen, key, &keylen) != 0 || keylen != SSO_KEY_LEN) {
        ret = 1; // authenticated decryption failed: wrong old password
        goto out;
    }
    if (pinlock_sso_wrap(key, new_password, &salt64, &kwrap64, &pwblob64) != 0) goto out;

    {
        size_t need = strlen(lines[0]) + strlen(lines[1]) + strlen(lines[2])
            + strlen(salt64) + strlen(kwrap64) + strlen(pwblob64) + 7;
        char *content = malloc(need);
        if (!content) goto out;
        snprintf(content, need, "%s\n%s\n%s\n%s\n%s\n%s\n",
                 lines[0], lines[1], lines[2], salt64, kwrap64, pwblob64);

        // Replace via tmp file + rename so a crash never leaves a torn
        // record, preserving the original owner (this runs as root from
        // the passwd stack, often against a user-owned file).
        struct stat st;
        char tmp[1024];
        int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
        if (n < 0 || n >= (int)sizeof(tmp) || lstat(path, &st) != 0) {
            free(content);
            goto out;
        }
        int fd = open(tmp, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0600);
        if (fd < 0) { free(content); goto out; }
        size_t len = strlen(content);
        int write_ok = 1;
        if (geteuid() == 0 && fchown(fd, st.st_uid, st.st_gid) != 0) write_ok = 0;
        const char *w = content;
        while (write_ok && len > 0) {
            ssize_t wn = write(fd, w, len);
            if (wn <= 0) { write_ok = 0; break; }
            w += wn;
            len -= (size_t)wn;
        }
        if (write_ok && fsync(fd) != 0) write_ok = 0;
        if (close(fd) != 0) write_ok = 0;
        if (write_ok && rename(tmp, path) == 0) ret = 0;
        else unlink(tmp);
        free(content);
    }

out:
    wipe(wrapkey, sizeof(wrapkey));
    wipe(key, sizeof(key));
    free(salt64); free(kwrap64); free(pwblob64);
    free(text);
    return ret;
}

#endif // HAVE_TPM2

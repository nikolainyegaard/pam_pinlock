#define _GNU_SOURCE
#include "pinlock_record.h"
#include "pinlock_tpm2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/random.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

#define TPM2_SECRET_LEN 32

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

// Strip the handle/parameter/session index from format-one TPM error
// codes so they compare against the bare error constants.
static TSS2_RC base_rc(TSS2_RC rc) {
    if ((rc & 0xFFFF0000) != 0) return rc; // not the TPM layer
    if (rc & TPM2_RC_FMT1) return TPM2_RC_FMT1 | (rc & 0x3F);
    return rc;
}

static int classify_rc(TSS2_RC rc) {
    TSS2_RC b = base_rc(rc);
    if (b == TPM2_RC_AUTH_FAIL || b == TPM2_RC_BAD_AUTH) return PINLOCK_VERIFY_FAIL;
    if (b == TPM2_RC_LOCKOUT) return PINLOCK_VERIFY_LOCKOUT;
    return PINLOCK_VERIFY_UNAVAILABLE;
}

/* ---------- base64 ---------- */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const uint8_t *in, size_t len) {
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

static int b64_decode(const char *in, size_t inlen, uint8_t *out, size_t cap, size_t *outlen) {
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
            out[o++] = (uint8_t)(v >> bits);
        }
    }
    *outlen = o;
    return 0;
}

/* ---------- TPM plumbing ---------- */

static TSS2_RC open_ctx(const char *tcti_conf, ESYS_CONTEXT **ctx, TSS2_TCTI_CONTEXT **tcti) {
    if (tcti_conf && !*tcti_conf) tcti_conf = NULL; // empty means library default
    TSS2_RC rc = Tss2_TctiLdr_Initialize(tcti_conf, tcti);
    if (rc != TSS2_RC_SUCCESS) return rc;
    rc = Esys_Initialize(ctx, *tcti, NULL);
    if (rc != TSS2_RC_SUCCESS) Tss2_TctiLdr_Finalize(tcti);
    return rc;
}

static void close_ctx(ESYS_CONTEXT **ctx, TSS2_TCTI_CONTEXT **tcti) {
    if (*ctx) Esys_Finalize(ctx);
    if (*tcti) Tss2_TctiLdr_Finalize(tcti);
}

// Standard ECC storage primary template (TCG provisioning guidance).
// Deterministic for a given TPM, so it is recreated on each use instead
// of managing a persistent handle. noDA on the primary is deliberate:
// dictionary attack protection belongs to the sealed object.
static const TPM2B_PUBLIC srk_template = {
    .publicArea = {
        .type = TPM2_ALG_ECC,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                            TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_RESTRICTED |
                            TPMA_OBJECT_DECRYPT | TPMA_OBJECT_USERWITHAUTH |
                            TPMA_OBJECT_NODA,
        .parameters.eccDetail = {
            .symmetric = {
                .algorithm = TPM2_ALG_AES,
                .keyBits.aes = 128,
                .mode.aes = TPM2_ALG_CFB,
            },
            .scheme.scheme = TPM2_ALG_NULL,
            .curveID = TPM2_ECC_NIST_P256,
            .kdf.scheme = TPM2_ALG_NULL,
        },
    },
};

static TSS2_RC make_primary(ESYS_CONTEXT *ctx, ESYS_TR *primary) {
    TPM2B_SENSITIVE_CREATE sens = {0};
    TPM2B_DATA outside = {0};
    TPML_PCR_SELECTION pcrs = {0};
    return Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              &sens, &srk_template, &outside, &pcrs,
                              primary, NULL, NULL, NULL, NULL);
}

// Salted HMAC session with AES-128-CFB parameter encryption. The salt
// is encrypted to the primary, so a bus sniffer sees neither the PIN
// (HMAC'd, never transmitted) nor the sealed secret (response encrypted).
static TSS2_RC make_session(ESYS_CONTEXT *ctx, ESYS_TR primary, ESYS_TR *session) {
    TPMT_SYM_DEF sym = {
        .algorithm = TPM2_ALG_AES,
        .keyBits.aes = 128,
        .mode.aes = TPM2_ALG_CFB,
    };
    TSS2_RC rc = Esys_StartAuthSession(ctx, primary, ESYS_TR_NONE,
                                       ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       NULL, TPM2_SE_HMAC, &sym, TPM2_ALG_SHA256,
                                       session);
    if (rc != TSS2_RC_SUCCESS) return rc;
    return Esys_TRSess_SetAttributes(ctx, *session,
        TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT | TPMA_SESSION_CONTINUESESSION,
        0xFF);
}

static int pin_to_auth(const char *pin, TPM2B_AUTH *auth) {
    size_t len = strlen(pin);
    if (len == 0 || len > PINLOCK_TPM2_MAX_PIN) return -1;
    auth->size = (UINT16)len;
    memcpy(auth->buffer, pin, len);
    return 0;
}

/* ---------- record text ---------- */

// Record layout: PINLOCK_TPM2_HEADER, then base64 TPM2B_PUBLIC, then
// base64 TPM2B_PRIVATE, one per line.

static int parse_record(const char *text, TPM2B_PUBLIC *pub, TPM2B_PRIVATE *priv) {
    const char *l1 = strchr(text, '\n');
    if (!l1) return -1;
    const char *l2 = strchr(l1 + 1, '\n');
    if (!l2) return -1;
    const char *end = strchr(l2 + 1, '\n');
    if (!end) end = l2 + 1 + strlen(l2 + 1);

    uint8_t pbuf[sizeof(TPM2B_PUBLIC)], sbuf[sizeof(TPM2B_PRIVATE)];
    size_t plen, slen, off;
    if (b64_decode(l1 + 1, (size_t)(l2 - l1 - 1), pbuf, sizeof(pbuf), &plen) != 0) return -1;
    if (b64_decode(l2 + 1, (size_t)(end - l2 - 1), sbuf, sizeof(sbuf), &slen) != 0) return -1;
    off = 0;
    if (Tss2_MU_TPM2B_PUBLIC_Unmarshal(pbuf, plen, &off, pub) != TSS2_RC_SUCCESS) return -1;
    off = 0;
    if (Tss2_MU_TPM2B_PRIVATE_Unmarshal(sbuf, slen, &off, priv) != TSS2_RC_SUCCESS) return -1;
    return 0;
}

/* ---------- public API ---------- */

int pinlock_tpm2_available(const char *tcti_conf) {
    ESYS_CONTEXT *ctx = NULL;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    if (open_ctx(tcti_conf, &ctx, &tcti) != TSS2_RC_SUCCESS) return 0;
    TPMS_CAPABILITY_DATA *cap = NULL;
    TSS2_RC rc = Esys_GetCapability(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER, 1,
                                    NULL, &cap);
    Esys_Free(cap);
    close_ctx(&ctx, &tcti);
    return rc == TSS2_RC_SUCCESS;
}

int pinlock_tpm2_seal(const char *tcti_conf, const char *pin, char **record_out) {
    *record_out = NULL;

    TPM2B_AUTH auth = {0};
    if (pin_to_auth(pin, &auth) != 0) return -1;

    ESYS_CONTEXT *ctx = NULL;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    if (open_ctx(tcti_conf, &ctx, &tcti) != TSS2_RC_SUCCESS) {
        wipe(&auth, sizeof(auth));
        return -1;
    }

    int ret = -1;
    ESYS_TR primary = ESYS_TR_NONE, session = ESYS_TR_NONE;
    TPM2B_PRIVATE *out_priv = NULL;
    TPM2B_PUBLIC *out_pub = NULL;
    TPM2B_SENSITIVE_CREATE sens = {0};

    if (make_primary(ctx, &primary) != TSS2_RC_SUCCESS) goto out;
    if (make_session(ctx, primary, &session) != TSS2_RC_SUCCESS) goto out;

    // Sealed object: no TPMA_OBJECT_NODA, so the TPM's dictionary
    // attack lockout throttles wrong-PIN attempts in hardware.
    TPM2B_PUBLIC seal_pub = {
        .publicArea = {
            .type = TPM2_ALG_KEYEDHASH,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                TPMA_OBJECT_USERWITHAUTH,
            .parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL,
        },
    };
    sens.sensitive.userAuth = auth;
    sens.sensitive.data.size = TPM2_SECRET_LEN;
    if (getrandom(sens.sensitive.data.buffer, TPM2_SECRET_LEN, 0) != TPM2_SECRET_LEN) goto out;

    TPM2B_DATA outside = {0};
    TPML_PCR_SELECTION pcrs = {0};
    TSS2_RC rc = Esys_Create(ctx, primary, session, ESYS_TR_NONE, ESYS_TR_NONE,
                             &sens, &seal_pub, &outside, &pcrs,
                             &out_priv, &out_pub, NULL, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) goto out;

    uint8_t pbuf[sizeof(TPM2B_PUBLIC)], sbuf[sizeof(TPM2B_PRIVATE)];
    size_t poff = 0, soff = 0;
    if (Tss2_MU_TPM2B_PUBLIC_Marshal(out_pub, pbuf, sizeof(pbuf), &poff) != TSS2_RC_SUCCESS) goto out;
    if (Tss2_MU_TPM2B_PRIVATE_Marshal(out_priv, sbuf, sizeof(sbuf), &soff) != TSS2_RC_SUCCESS) goto out;

    char *p64 = b64_encode(pbuf, poff);
    char *s64 = b64_encode(sbuf, soff);
    if (p64 && s64) {
        size_t need = strlen(PINLOCK_TPM2_HEADER) + strlen(p64) + strlen(s64) + 4;
        char *record = malloc(need);
        if (record) {
            snprintf(record, need, "%s\n%s\n%s\n", PINLOCK_TPM2_HEADER, p64, s64);
            *record_out = record;
            ret = 0;
        }
    }
    free(p64);
    free(s64);

out:
    wipe(&auth, sizeof(auth));
    wipe(&sens, sizeof(sens));
    Esys_Free(out_priv);
    Esys_Free(out_pub);
    if (session != ESYS_TR_NONE) Esys_FlushContext(ctx, session);
    if (primary != ESYS_TR_NONE) Esys_FlushContext(ctx, primary);
    close_ctx(&ctx, &tcti);
    return ret;
}

int pinlock_tpm2_verify(const char *tcti_conf, const char *record_text, const char *pin) {
    TPM2B_AUTH auth = {0};
    if (pin_to_auth(pin, &auth) != 0) {
        wipe(&auth, sizeof(auth));
        return PINLOCK_VERIFY_FAIL;
    }

    TPM2B_PUBLIC pub;
    TPM2B_PRIVATE priv;
    if (parse_record(record_text, &pub, &priv) != 0) {
        wipe(&auth, sizeof(auth));
        return PINLOCK_VERIFY_UNAVAILABLE;
    }

    ESYS_CONTEXT *ctx = NULL;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    if (open_ctx(tcti_conf, &ctx, &tcti) != TSS2_RC_SUCCESS) {
        wipe(&auth, sizeof(auth));
        return PINLOCK_VERIFY_UNAVAILABLE;
    }

    int result = PINLOCK_VERIFY_UNAVAILABLE;
    ESYS_TR primary = ESYS_TR_NONE, session = ESYS_TR_NONE, obj = ESYS_TR_NONE;
    TSS2_RC rc;

    rc = make_primary(ctx, &primary);
    if (rc != TSS2_RC_SUCCESS) { result = classify_rc(rc); goto out; }
    rc = make_session(ctx, primary, &session);
    if (rc != TSS2_RC_SUCCESS) { result = classify_rc(rc); goto out; }

    rc = Esys_Load(ctx, primary, session, ESYS_TR_NONE, ESYS_TR_NONE, &priv, &pub, &obj);
    if (rc != TSS2_RC_SUCCESS) {
        // A record sealed by a different or since-cleared TPM fails
        // here with TPM2_RC_INTEGRITY; that is unavailability, not a
        // wrong PIN.
        result = base_rc(rc) == TPM2_RC_LOCKOUT
            ? PINLOCK_VERIFY_LOCKOUT : PINLOCK_VERIFY_UNAVAILABLE;
        goto out;
    }

    rc = Esys_TR_SetAuth(ctx, obj, &auth);
    if (rc != TSS2_RC_SUCCESS) goto out;

    TPM2B_SENSITIVE_DATA *secret = NULL;
    rc = Esys_Unseal(ctx, obj, session, ESYS_TR_NONE, ESYS_TR_NONE, &secret);
    if (rc == TSS2_RC_SUCCESS) {
        wipe(secret->buffer, secret->size);
        Esys_Free(secret);
        result = PINLOCK_VERIFY_OK;
    } else {
        result = classify_rc(rc);
    }

out:
    wipe(&auth, sizeof(auth));
    if (obj != ESYS_TR_NONE) Esys_FlushContext(ctx, obj);
    if (session != ESYS_TR_NONE) Esys_FlushContext(ctx, session);
    if (primary != ESYS_TR_NONE) Esys_FlushContext(ctx, primary);
    close_ctx(&ctx, &tcti);
    return result;
}

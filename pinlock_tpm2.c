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

// Creating the primary is by far the slowest TPM operation (hundreds of
// ms on discrete chips), so enrollment persists the SRK and verification
// reuses it. Two candidate slots: the conventional shared SRK location
// (TCG provisioning guidance, also used by systemd) when it holds our
// key, and pinlock's own slot when the shared one belongs to someone
// else (a previous Windows install commonly leaves its RSA SRK there).
// Verification falls back to a freshly created transient primary when
// neither slot has the record's parent, so records always stay usable.
#define PINLOCK_SRK_HANDLE_SHARED 0x81000001
#define PINLOCK_SRK_HANDLE_OWN    0x8100F1CC

// Own slot first: probing an empty slot is nearly free, but attempting
// an unseal under a foreign key in the shared slot (the ex-Windows
// case) costs a whole session plus a failed load on every auth.
static const TPM2_HANDLE srk_slots[] = { PINLOCK_SRK_HANDLE_OWN, PINLOCK_SRK_HANDLE_SHARED };

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
    // Keep tss2 library chatter off the caller's stderr; the PAM module
    // can be running inside sudo or a screen locker. Export TSS2_LOG
    // before the call to override for debugging.
    setenv("TSS2_LOG", "all+NONE", 0);
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

static int parse_record(const char *text, TPM2B_PUBLIC *pub, TPM2B_PRIVATE *priv, int *sso) {
    const char *l1 = strchr(text, '\n');
    if (!l1) return -1;
    *sso = (size_t)(l1 - text) == strlen(PINLOCK_TPM2_HEADER_SSO)
        && strncmp(text, PINLOCK_TPM2_HEADER_SSO, strlen(PINLOCK_TPM2_HEADER_SSO)) == 0;
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

int pinlock_tpm2_da_info(const char *tcti_conf, pinlock_tpm2_da_info_t *info) {
    memset(info, 0, sizeof(*info));

    ESYS_CONTEXT *ctx = NULL;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    if (open_ctx(tcti_conf, &ctx, &tcti) != TSS2_RC_SUCCESS) return -1;

    TPMS_CAPABILITY_DATA *cap = NULL;
    TSS2_RC rc = Esys_GetCapability(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    TPM2_CAP_TPM_PROPERTIES, TPM2_PT_VAR, TPM2_MAX_TPM_PROPERTIES,
                                    NULL, &cap);
    close_ctx(&ctx, &tcti);
    if (rc != TSS2_RC_SUCCESS || !cap) {
        Esys_Free(cap);
        return -1;
    }

    for (uint32_t i = 0; i < cap->data.tpmProperties.count; i++) {
        const TPMS_TAGGED_PROPERTY *p = &cap->data.tpmProperties.tpmProperty[i];
        switch (p->property) {
        case TPM2_PT_LOCKOUT_COUNTER:  info->lockout_counter = p->value; break;
        case TPM2_PT_MAX_AUTH_FAIL:    info->max_auth_fail = p->value; break;
        case TPM2_PT_LOCKOUT_INTERVAL: info->lockout_interval = p->value; break;
        case TPM2_PT_LOCKOUT_RECOVERY: info->lockout_recovery = p->value; break;
        case TPM2_PT_PERMANENT:
            info->in_lockout = (p->value & TPMA_PERMANENT_INLOCKOUT) != 0;
            info->lockout_auth_set = (p->value & TPMA_PERMANENT_LOCKOUTAUTHSET) != 0;
            break;
        }
    }
    Esys_Free(cap);
    return 0;
}

int pinlock_tpm2_seal(const char *tcti_conf, const char *pin, const char *sso_password, char **record_out) {
    *record_out = NULL;

    size_t sso_len = sso_password ? strlen(sso_password) : 0;
    if (sso_len > PINLOCK_TPM2_MAX_SSO || (sso_password && sso_len == 0)) return -1;
    const char *header = sso_password ? PINLOCK_TPM2_HEADER_SSO : PINLOCK_TPM2_HEADER;

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
    if (sso_password) {
        sens.sensitive.data.size = (UINT16)sso_len;
        memcpy(sens.sensitive.data.buffer, sso_password, sso_len);
    } else {
        sens.sensitive.data.size = TPM2_SECRET_LEN;
        if (getrandom(sens.sensitive.data.buffer, TPM2_SECRET_LEN, 0) != TPM2_SECRET_LEN) goto out;
    }

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
        size_t need = strlen(header) + strlen(p64) + strlen(s64) + 4;
        char *record = malloc(need);
        if (record) {
            snprintf(record, need, "%s\n%s\n%s\n", header, p64, s64);
            *record_out = record;
            ret = 0;
        }
    }
    free(p64);
    free(s64);

    // Best effort: make sure the SRK is persisted where verification
    // will find it, so it skips the expensive primary creation. A slot
    // holding a foreign key is left alone; skipping entirely is
    // harmless (verification falls back to a transient primary).
    if (ret == 0) {
        TPM2B_NAME *primary_name = NULL;
        if (Esys_TR_GetName(ctx, primary, &primary_name) == TSS2_RC_SUCCESS && primary_name) {
            int found = 0;
            TPM2_HANDLE free_slot = 0;
            for (size_t i = 0; i < sizeof(srk_slots)/sizeof(srk_slots[0]) && !found; i++) {
                ESYS_TR cand = ESYS_TR_NONE;
                if (Esys_TR_FromTPMPublic(ctx, srk_slots[i],
                                          ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                          &cand) != TSS2_RC_SUCCESS) {
                    if (!free_slot) free_slot = srk_slots[i];
                    continue;
                }
                TPM2B_NAME *cand_name = NULL;
                if (Esys_TR_GetName(ctx, cand, &cand_name) == TSS2_RC_SUCCESS && cand_name
                        && cand_name->size == primary_name->size
                        && memcmp(cand_name->name, primary_name->name, cand_name->size) == 0)
                    found = 1;
                Esys_Free(cand_name);
                Esys_TR_Close(ctx, &cand);
            }
            if (!found && free_slot) {
                ESYS_TR persisted = ESYS_TR_NONE;
                if (Esys_EvictControl(ctx, ESYS_TR_RH_OWNER, primary,
                                      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                      free_slot, &persisted) == TSS2_RC_SUCCESS
                        && persisted != ESYS_TR_NONE)
                    Esys_TR_Close(ctx, &persisted);
            }
        }
        Esys_Free(primary_name);
    }

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

// One unseal attempt under a given parent. Sets *load_integrity when
// Load failed because the blob was not sealed under this parent key.
// When secret_out is non-NULL, a successful unseal stores the payload
// there as a NUL-terminated heap string (caller wipes and frees).
static int unseal_under_parent(ESYS_CONTEXT *ctx, ESYS_TR parent,
                               const TPM2B_PUBLIC *pub, const TPM2B_PRIVATE *priv,
                               const TPM2B_AUTH *auth, int *load_integrity,
                               char **secret_out) {
    *load_integrity = 0;
    ESYS_TR session = ESYS_TR_NONE, obj = ESYS_TR_NONE;

    TSS2_RC rc = make_session(ctx, parent, &session);
    if (rc != TSS2_RC_SUCCESS) return classify_rc(rc);

    rc = Esys_Load(ctx, parent, session, ESYS_TR_NONE, ESYS_TR_NONE, priv, pub, &obj);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_FlushContext(ctx, session);
        if (base_rc(rc) == TPM2_RC_INTEGRITY) *load_integrity = 1;
        return base_rc(rc) == TPM2_RC_LOCKOUT
            ? PINLOCK_VERIFY_LOCKOUT : PINLOCK_VERIFY_UNAVAILABLE;
    }

    rc = Esys_TR_SetAuth(ctx, obj, auth);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_FlushContext(ctx, obj);
        Esys_FlushContext(ctx, session);
        return PINLOCK_VERIFY_UNAVAILABLE;
    }

    TPM2B_SENSITIVE_DATA *secret = NULL;
    rc = Esys_Unseal(ctx, obj, session, ESYS_TR_NONE, ESYS_TR_NONE, &secret);
    Esys_FlushContext(ctx, obj);
    Esys_FlushContext(ctx, session);

    if (rc == TSS2_RC_SUCCESS) {
        if (secret_out) {
            char *copy = malloc((size_t)secret->size + 1);
            if (copy) {
                memcpy(copy, secret->buffer, secret->size);
                copy[secret->size] = '\0';
            }
            *secret_out = copy;
        }
        wipe(secret->buffer, secret->size);
        Esys_Free(secret);
        return PINLOCK_VERIFY_OK;
    }
    return classify_rc(rc);
}

int pinlock_tpm2_verify(const char *tcti_conf, const char *record_text, const char *pin, char **sso_secret_out) {
    TPM2B_AUTH auth = {0};
    if (pin_to_auth(pin, &auth) != 0) {
        wipe(&auth, sizeof(auth));
        return PINLOCK_VERIFY_FAIL;
    }

    if (sso_secret_out) *sso_secret_out = NULL;

    TPM2B_PUBLIC pub;
    TPM2B_PRIVATE priv;
    int sso = 0;
    if (parse_record(record_text, &pub, &priv, &sso) != 0) {
        wipe(&auth, sizeof(auth));
        return PINLOCK_VERIFY_UNAVAILABLE;
    }
    char **secret_out = (sso && sso_secret_out) ? sso_secret_out : NULL;

    ESYS_CONTEXT *ctx = NULL;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    if (open_ctx(tcti_conf, &ctx, &tcti) != TSS2_RC_SUCCESS) {
        wipe(&auth, sizeof(auth));
        return PINLOCK_VERIFY_UNAVAILABLE;
    }

    int result = PINLOCK_VERIFY_UNAVAILABLE;
    int load_integrity = 0;
    ESYS_TR parent = ESYS_TR_NONE;

    // Fast path: a persisted SRK. A slot that is empty or holds a key
    // that is not the record's parent moves on to the next candidate;
    // the transient primary is the last resort.
    TSS2_RC rc;
    for (size_t i = 0; i < sizeof(srk_slots)/sizeof(srk_slots[0]); i++) {
        rc = Esys_TR_FromTPMPublic(ctx, srk_slots[i],
                                   ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &parent);
        if (rc != TSS2_RC_SUCCESS) continue;
        result = unseal_under_parent(ctx, parent, &pub, &priv, &auth, &load_integrity, secret_out);
        Esys_TR_Close(ctx, &parent);
        if (result != PINLOCK_VERIFY_UNAVAILABLE || !load_integrity)
            goto out;
    }

    parent = ESYS_TR_NONE;
    rc = make_primary(ctx, &parent);
    if (rc != TSS2_RC_SUCCESS) {
        result = classify_rc(rc);
        goto out;
    }
    result = unseal_under_parent(ctx, parent, &pub, &priv, &auth, &load_integrity, secret_out);
    Esys_FlushContext(ctx, parent);

out:
    wipe(&auth, sizeof(auth));
    close_ctx(&ctx, &tcti);
    return result;
}

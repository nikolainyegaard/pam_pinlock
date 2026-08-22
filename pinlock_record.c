#define _GNU_SOURCE
#include "pinlock_record.h"

#include <argon2.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Read first line from file
static int read_first_line(const char *path, char **out) {
    *out = NULL;
#ifdef O_NOFOLLOW
    int fd = open(path, O_RDONLY|O_NOFOLLOW);
#else
    int fd = open(path, O_RDONLY);
#endif
    if (fd < 0) return -1;
    FILE *f = fdopen(fd,"r");
    if(!f) { close(fd); return -1; }
    size_t cap=0; ssize_t n=getline(out,&cap,f); fclose(f);
    if(n<=0) { free(*out); *out=NULL; return -1; }
    while(n>0 && ((*out)[n-1]=='\n'||(*out)[n-1]=='\r')) (*out)[--n]=0;
    return 0;
}

pinlock_record_type_t pinlock_record_type(const char *first_line) {
    if (first_line && strncmp(first_line, "$argon2id$", 10) == 0) return PINLOCK_RECORD_ARGON2;
    return PINLOCK_RECORD_UNKNOWN;
}

int pinlock_verify_pin(const char *path, const char *pin) {
    char *first = NULL;
    if (read_first_line(path, &first) != 0 || !first) return PINLOCK_VERIFY_UNREADABLE;

    int result;
    switch (pinlock_record_type(first)) {
    case PINLOCK_RECORD_ARGON2:
        result = argon2id_verify(first, pin, strlen(pin)) == ARGON2_OK
            ? PINLOCK_VERIFY_OK : PINLOCK_VERIFY_FAIL;
        break;
    default:
        result = PINLOCK_VERIFY_FAIL;
        break;
    }

    free(first);
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

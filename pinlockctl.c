#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <ctype.h>

#include "pinlock_record.h"
#ifdef HAVE_TPM2
#include "pinlock_tpm2.h"
#include <security/pam_appl.h>

// PAM conversation that answers every prompt with the given password.
static int pw_check_conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {
    struct pam_response *r = calloc((size_t)n, sizeof(*r));
    if (!r) return PAM_CONV_ERR;
    for (int i = 0; i < n; i++) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON)
            r[i].resp = strdup((const char *)data);
    }
    *resp = r;
    return PAM_SUCCESS;
}

// Verify the account password before sealing it: a sealed typo would
// quietly break wallet unlocking on every PIN sign-in.
static int verify_account_password(const char *user, const char *password) {
    struct stat st;
    const char *service = stat("/etc/pam.d/sshd", &st) == 0 ? "sshd" : "login";
    struct pam_conv conv = { pw_check_conv, (void *)password };
    pam_handle_t *pamh = NULL;
    if (pam_start(service, user, &conv, &pamh) != PAM_SUCCESS) return -1;
    int rc = pam_authenticate(pamh, PAM_SILENT);
    pam_end(pamh, rc);
    return rc == PAM_SUCCESS ? 0 : -1;
}
#endif

// Configuration structure (same as PAM module)
typedef struct {
    char pin_dir[1024];
    char tpm2_tcti[256];
    int min_length;
    int max_length;
    int require_digits_only;
    int max_attempts;
    int lockout_window;
    int rate_limit_window;
    int enable_lockout;
    int lockout_duration;
    int log_attempts;
    int log_success;
    int log_failures;
    int debug;
    int allow_user_config;
    int lockout_fails_auth;
} pinlock_config_t;

static void die(const char *msg) { perror(msg); exit(1); }

static void usage(const char *prog) {
    printf("Usage: %s [--pin-dir DIR] <command> [username]\n", prog);
    printf("Options:\n");
    printf("  --pin-dir DIR   Override PIN storage directory for this command\n");
    printf("  --tpm           Seal the PIN in the TPM instead of storing a hash (enroll/set)\n");
    printf("  --no-tpm        Store a hash without offering TPM sealing (enroll/set)\n");
    printf("  --sso           Also seal the account password so PIN sign-in unlocks KWallet (with --tpm)\n");
    printf("  --no-sso        Never offer to seal the account password\n");
    printf("Commands:\n");
    printf("  enroll, set    Set a new PIN for the user\n");
    printf("  change         Change the PIN (asks for the current PIN first)\n");
    printf("  reset          Reset a forgotten PIN using the account password\n");
    printf("  remove         Remove the PIN for the user\n");
    printf("  status         Show whether a PIN is set\n");
    printf("  tpm-status     Show TPM availability and dictionary attack lockout state\n");
    printf("  unlock         Clear rate limiting/lockout for user\n");
    printf("  check          Check PIN storage configuration and permissions\n");
    printf("  config         Show current configuration\n");
    printf("  help           Show this help message\n");
    exit(0);
}

static char *get_username(int argc, char **argv, int cmd_index) {
    if (argc > cmd_index + 1 && argv[cmd_index + 1] && *argv[cmd_index + 1]) return strdup(argv[cmd_index + 1]);

    char buf[128];
    fprintf(stderr, "Enter username: ");
    fflush(stderr);
    if (!fgets(buf, sizeof(buf), stdin)) return NULL;
    size_t len = strlen(buf);
    while (len > 0 && (buf[len-1]=='\n' || buf[len-1]=='\r')) buf[--len]=0;
    if (len==0) return NULL;
    return strdup(buf);
}

static char *get_pinlock_dir(const char *user, const pinlock_config_t *config) {
    static char dir[1024];

    if (config->pin_dir[0]) {
        int n = snprintf(dir, sizeof(dir), "%s", config->pin_dir);
        if (n < 0 || n >= (int)sizeof(dir)) return NULL;
        return dir;
    }

    struct passwd *pw = getpwnam(user);
    if (!pw) return NULL;
    int n = snprintf(dir, sizeof(dir), "%s/.pinlock", pw->pw_dir);
    if (n < 0 || n >= (int)sizeof(dir)) return NULL;
    return dir;
}

static int system_pin_dir_enabled(const pinlock_config_t *config) {
    return config->pin_dir[0] != '\0';
}

static int ensure_dir(const char *dir, const struct passwd *pw, int system_dir) {
    struct stat st;
    if (lstat(dir, &st) == 0) return S_ISDIR(st.st_mode) ? 0 : -1;
    if (errno == ENOENT) {
        if (mkdir(dir, 0700) != 0) return -1;
        if (!system_dir && pw && geteuid() == 0 && chown(dir, pw->pw_uid, pw->pw_gid) != 0) return -1;
        return 0;
    }
    return -1;
}

static int write_all(int fd, const char *data, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, data, len);
        if (n <= 0) return -1;
        data += n;
        len -= (size_t)n;
    }
    return 0;
}

static int write_file_restrict(const char *dir, const char *path, const char *data, const struct passwd *pw, int system_dir) {
    char tmp[1024];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
    if (n < 0 || n >= (int)sizeof(tmp)) return -1;

#ifdef O_NOFOLLOW
    int fd = open(tmp, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0600);
#else
    int fd = open(tmp, O_WRONLY|O_CREAT|O_EXCL, 0600);
#endif
    if (fd < 0) return -1;

    if (!system_dir && pw && geteuid() == 0 && fchown(fd, pw->pw_uid, pw->pw_gid) != 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }

    if (write_all(fd, data, strlen(data)) != 0 || fsync(fd) != 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    if (close(fd) != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }

#ifdef O_DIRECTORY
    int dirfd = open(dir, O_RDONLY|O_DIRECTORY);
    if (dirfd >= 0) {
        fsync(dirfd);
        close(dirfd);
    }
#endif

    return 0;
}

static void noecho(int off) {
    struct termios t;
    if (tcgetattr(STDIN_FILENO, &t) == 0) {
        if (off) t.c_lflag &= ~ECHO;
        else t.c_lflag |= ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
    }
}

static char *prompt_hidden(const char *label) {
    fprintf(stderr, "%s", label); fflush(stderr);
    noecho(1);
    char *line = NULL; size_t cap=0;
    ssize_t n = getline(&line, &cap, stdin);
    noecho(0); fprintf(stderr, "\n");
    if (n <=0) { free(line); return NULL; }
    while(n>0 && (line[n-1]=='\n'||line[n-1]=='\r')) line[--n]=0;
    return line;
}

static void load_default_config(pinlock_config_t *config) {
    config->pin_dir[0] = '\0';
    config->tpm2_tcti[0] = '\0';
    config->min_length = 6;
    config->max_length = 32;
    config->require_digits_only = 1;
    config->max_attempts = 5;
    config->lockout_window = 300;
    config->rate_limit_window = 60;
    config->enable_lockout = 0;
    config->lockout_duration = 900;
    config->log_attempts = 1;
    config->log_success = 1;
    config->log_failures = 1;
    config->debug = 0;
    config->allow_user_config = 0;
    config->lockout_fails_auth = 0;
}

static int parse_bool(const char *value) {
    if (!value) return 0;
    return (strcasecmp(value, "yes") == 0 || 
            strcasecmp(value, "true") == 0 || 
            strcasecmp(value, "1") == 0);
}

static int parse_int_range(const char *value, int min, int max, int *out) {
    if (!value || !*value) return 0;

    errno = 0;
    char *end = NULL;
    long n = strtol(value, &end, 10);
    while (end && isspace((unsigned char)*end)) end++;
    if (errno || !end || *end || n < min || n > max) return 0;

    *out = (int)n;
    return 1;
}

static void strip_inline_comment(char *value) {
    char *hash = strchr(value, '#');
    if (hash) *hash = '\0';
}

static void trim_right(char *value) {
    char *end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1])) *--end = '\0';
}

static void validate_config(pinlock_config_t *config) {
    if (config->min_length < 1) config->min_length = 1;
    if (config->max_length < config->min_length) config->max_length = config->min_length;
    if (config->max_length > 128) config->max_length = 128;
    if (config->max_attempts < 1) config->max_attempts = 1;
    if (config->rate_limit_window < 1) config->rate_limit_window = 1;
    if (config->lockout_window < 0) config->lockout_window = 0;
    if (config->lockout_duration < 1) config->lockout_duration = 1;
}

static void load_config_file(const char *path, pinlock_config_t *config) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // Skip comments and empty lines
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        
        // Find the = sign
        char *eq = strchr(p, '=');
        if (!eq) continue;
        
        *eq = '\0';
        char *key = p;
        char *value = eq + 1;
        
        // Trim whitespace
        trim_right(key);
        while (isspace((unsigned char)*value)) value++;
        strip_inline_comment(value);
        trim_right(value);
        
        // Parse configuration values
        int parsed = 0;
        if (strcmp(key, "pin_dir") == 0) {
            if (!*value || *value == '/') snprintf(config->pin_dir, sizeof(config->pin_dir), "%s", value);
        }
        else if (strcmp(key, "tpm2_tcti") == 0) snprintf(config->tpm2_tcti, sizeof(config->tpm2_tcti), "%s", value);
        else if (strcmp(key, "min_length") == 0 && parse_int_range(value, 1, 128, &parsed)) config->min_length = parsed;
        else if (strcmp(key, "max_length") == 0 && parse_int_range(value, 1, 128, &parsed)) config->max_length = parsed;
        else if (strcmp(key, "require_digits_only") == 0) config->require_digits_only = parse_bool(value);
        else if (strcmp(key, "max_attempts") == 0 && parse_int_range(value, 1, 50, &parsed)) config->max_attempts = parsed;
        else if (strcmp(key, "lockout_window") == 0 && parse_int_range(value, 0, 86400, &parsed)) config->lockout_window = parsed;
        else if (strcmp(key, "rate_limit_window") == 0 && parse_int_range(value, 1, 86400, &parsed)) config->rate_limit_window = parsed;
        else if (strcmp(key, "enable_lockout") == 0) config->enable_lockout = parse_bool(value);
        else if (strcmp(key, "lockout_duration") == 0 && parse_int_range(value, 1, 604800, &parsed)) config->lockout_duration = parsed;
        else if (strcmp(key, "max_lockout_attempts") == 0) continue;
        else if (strcmp(key, "log_attempts") == 0) config->log_attempts = parse_bool(value);
        else if (strcmp(key, "log_success") == 0) config->log_success = parse_bool(value);
        else if (strcmp(key, "log_failures") == 0) config->log_failures = parse_bool(value);
        else if (strcmp(key, "debug") == 0) config->debug = parse_bool(value);
        else if (strcmp(key, "allow_user_config") == 0) config->allow_user_config = parse_bool(value);
        else if (strcmp(key, "lockout_fails_auth") == 0) config->lockout_fails_auth = parse_bool(value);
    }
    
    fclose(f);
}

static void load_config(const char *user, pinlock_config_t *config) {
    load_default_config(config);
    
    // Try system config first
    load_config_file("/etc/pinlock.conf", config);

    if (!config->allow_user_config) {
        validate_config(config);
        return;
    }

    // Try user config
    struct passwd *pw = getpwnam(user);
    if (pw) {
        char user_config[1024];
        int n = snprintf(user_config, sizeof(user_config), "%s/.pinlock/pinlock.conf", pw->pw_dir);
        if (n >= 0 && n < (int)sizeof(user_config)) load_config_file(user_config, config);
    }

    validate_config(config);
}

static int validate_pin(const char *pin, const pinlock_config_t *config) {
    if (!pin) return 0;
    
    size_t len = strlen(pin);
    if (len < (size_t)config->min_length || len > (size_t)config->max_length) {
        return 0;
    }
    
    if (config->require_digits_only) {
        for (size_t i = 0; i < len; i++) {
            if (!isdigit((unsigned char)pin[i])) return 0;
        }
    }
    
    return 1;
}

// Prompt for a new PIN with confirmation; returns a validated heap
// string or NULL after printing the reason (caller wipes and frees).
static char *prompt_new_pin(const pinlock_config_t *config) {
    char *p1 = prompt_hidden("Enter new PIN: ");
    if (!p1 || !*p1) {
        fprintf(stderr, "No PIN entered.\n");
        free(p1);
        return NULL;
    }
    if (!validate_pin(p1, config)) {
        fprintf(stderr, "PIN does not meet requirements:\n");
        fprintf(stderr, "  - Length: %d-%d characters\n", config->min_length, config->max_length);
        if (config->require_digits_only)
            fprintf(stderr, "  - Must contain only digits (0-9)\n");
        memset(p1, 0, strlen(p1));
        free(p1);
        return NULL;
    }
    char *p2 = prompt_hidden("Confirm PIN: ");
    if (!p2 || strcmp(p1, p2) != 0) {
        fprintf(stderr, "PINs do not match.\n");
        memset(p1, 0, strlen(p1));
        if (p2) memset(p2, 0, strlen(p2));
        free(p1);
        free(p2);
        return NULL;
    }
    memset(p2, 0, strlen(p2));
    free(p2);
    return p1;
}

// True when the record header carries the sso marker.
static int record_is_sso(const char *path) {
    char first[64];
#ifdef O_NOFOLLOW
    int fd = open(path, O_RDONLY|O_NOFOLLOW);
#else
    int fd = open(path, O_RDONLY);
#endif
    if (fd < 0) return 0;
    ssize_t n = read(fd, first, sizeof(first) - 1);
    close(fd);
    if (n <= 0) return 0;
    first[n] = '\0';
    first[strcspn(first, "\r\n")] = '\0';
    size_t len = strlen(first);
    return len >= 4 && strcmp(first + len - 4, " sso") == 0;
}

// Build a record for the chosen backend, printing the reason on
// failure. A non-NULL sso_pw also seals the account password (TPM
// records only; the caller has already verified it).
static char *make_record(const pinlock_config_t *config, const char *pin, const char *sso_pw, int use_tpm) {
    char *encoded = NULL;
    if (use_tpm) {
#ifdef HAVE_TPM2
        if (strlen(pin) > PINLOCK_TPM2_MAX_PIN) {
            fprintf(stderr, "TPM-sealed PINs may be at most %d characters\n", PINLOCK_TPM2_MAX_PIN);
            return NULL;
        }
        if (!pinlock_tpm2_available(config->tpm2_tcti)) {
            fprintf(stderr, "No usable TPM 2.0 found (check tpm2_tcti in /etc/pinlock.conf and /dev/tpmrm0 access)\n");
            return NULL;
        }
        if (pinlock_tpm2_seal(config->tpm2_tcti, pin, sso_pw, &encoded) != 0) {
            fprintf(stderr, "Failed to seal PIN in the TPM\n");
            return NULL;
        }
        return encoded;
#else
        (void)sso_pw;
        fprintf(stderr, "This build has no TPM support (rebuild with TPM2=1 and tpm2-tss headers)\n");
        return NULL;
#endif
    }
    int argon2_rc = 0;
    int rc = pinlock_record_create_argon2(pin, &encoded, &argon2_rc);
    if (rc == -1) die("urandom");
    if (rc == -2) die("malloc");
    if (rc != 0) {
        fprintf(stderr, "Failed to hash PIN (argon2 error %d)\n", argon2_rc);
        return NULL;
    }
    return encoded;
}

static void clear_rate_limit(const char *dir, const char *user) {
    char rl_path[1024];
    int n = snprintf(rl_path, sizeof(rl_path), "%s/%s.ratelimit", dir, user);
    if (n >= 0 && n < (int)sizeof(rl_path)) unlink(rl_path);
}

static int check_pin_dir_security(const char *dir, const struct passwd *pw, const pinlock_config_t *config, int verbose) {
    struct stat st;
    if (lstat(dir, &st) != 0) {
        if (verbose) printf("PIN directory: missing (%s)\n", dir);
        return -1;
    }

    int issues = 0;
    if (!S_ISDIR(st.st_mode)) {
        if (verbose) printf("PIN directory: not a directory (%s)\n", dir);
        return 1;
    }

    if (system_pin_dir_enabled(config)) {
        if (st.st_uid != 0) {
            if (verbose) printf("PIN directory: unsafe owner uid %ld, expected root\n", (long)st.st_uid);
            issues = 1;
        }
    } else if (st.st_uid != 0 && (!pw || st.st_uid != pw->pw_uid)) {
        if (verbose) printf("PIN directory: unsafe owner uid %ld\n", (long)st.st_uid);
        issues = 1;
    }

    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        if (verbose) printf("PIN directory: unsafe mode %04o, expected no group/world permissions\n", st.st_mode & 07777);
        issues = 1;
    }

    if (verbose && !issues) printf("PIN directory: ok (%s, mode %04o)\n", dir, st.st_mode & 07777);
    return issues;
}

static int check_pin_file_security(const char *path, const struct passwd *pw, const pinlock_config_t *config, int verbose) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (verbose) printf("PIN file: missing (%s)\n", path);
        return -1;
    }

    int issues = 0;
    if (!S_ISREG(st.st_mode)) {
        if (verbose) printf("PIN file: not a regular file (%s)\n", path);
        return 1;
    }

    if (system_pin_dir_enabled(config)) {
        if (st.st_uid != 0) {
            if (verbose) printf("PIN file: unsafe owner uid %ld, expected root\n", (long)st.st_uid);
            issues = 1;
        }
    } else if (st.st_uid != 0 && (!pw || st.st_uid != pw->pw_uid)) {
        if (verbose) printf("PIN file: unsafe owner uid %ld\n", (long)st.st_uid);
        issues = 1;
    }

    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        if (verbose) printf("PIN file: unsafe mode %04o, expected no group/world permissions\n", st.st_mode & 07777);
        issues = 1;
    }

    if (verbose && !issues) printf("PIN file: ok (%s, mode %04o)\n", path, st.st_mode & 07777);
    return issues;
}

static int show_storage_check(const char *user, const char *dir, const char *path, const struct passwd *pw, const pinlock_config_t *config) {
    printf("Storage check for user '%s':\n", user);
    printf("  Mode: %s\n", system_pin_dir_enabled(config) ? "system" : "per-user");
    printf("  Directory: %s\n", dir);
    printf("  PIN file: %s\n", path);

    int dir_status = check_pin_dir_security(dir, pw, config, 1);
    int file_status = check_pin_file_security(path, pw, config, 1);

    if (access(path, F_OK) == 0) {
        switch (pinlock_record_type_of_file(path)) {
        case PINLOCK_RECORD_TPM2:   printf("Record type: TPM-sealed\n"); break;
        case PINLOCK_RECORD_ARGON2: printf("Record type: argon2id hash\n"); break;
        default:                    printf("Record type: unrecognized or unreadable\n"); break;
        }
    }

    char rl_path[1024];
    int n = snprintf(rl_path, sizeof(rl_path), "%s/%s.ratelimit", dir, user);
    if (n >= 0 && n < (int)sizeof(rl_path)) {
        printf("Rate limit file: %s\n", access(rl_path, F_OK) == 0 ? rl_path : "not present");
    }

    return dir_status == 1 || file_status == 1;
}

static void show_config(const char *user, const pinlock_config_t *config) {
    printf("Configuration for user '%s':\n", user);
    printf("  PIN Storage:\n");
    printf("    Directory: %s\n", config->pin_dir[0] ? config->pin_dir : "~/.pinlock");

    printf("  PIN Requirements:\n");
    printf("    Minimum length: %d\n", config->min_length);
    printf("    Maximum length: %d\n", config->max_length);
    printf("    Digits only: %s\n", config->require_digits_only ? "yes" : "no");
    
    printf("  Rate Limiting:\n");
    printf("    Max attempts: %d\n", config->max_attempts);
    printf("    Rate limit window: %d seconds\n", config->rate_limit_window);
    printf("    Cooldown after rate limit: %d seconds\n", config->lockout_window);
    
    printf("  PIN Lockout:\n");
    printf("    Enabled: %s\n", config->enable_lockout ? "yes" : "no");
    printf("    Lockout duration: %d seconds\n", config->lockout_duration);
    
    printf("  Logging:\n");
    printf("    Log attempts: %s\n", config->log_attempts ? "yes" : "no");
    printf("    Log success: %s\n", config->log_success ? "yes" : "no");
    printf("    Log failures: %s\n", config->log_failures ? "yes" : "no");
    printf("    Debug: %s\n", config->debug ? "yes" : "no");
    printf("  Policy:\n");
    printf("    User config overrides: %s\n", config->allow_user_config ? "yes" : "no");
    printf("    PIN lockout fails auth: %s\n", config->lockout_fails_auth ? "yes" : "no");
}

static void unlock_user(const char *user, const char *dir) {
    char rl_path[1024];
    int n = snprintf(rl_path, sizeof(rl_path), "%s/%s.ratelimit", dir, user);
    if (n >= (int)sizeof(rl_path)) {
        printf("Error: path too long for user '%s'\n", user);
        return;
    }
    
    if (unlink(rl_path) == 0) {
        printf("Rate limiting/lockout cleared for user '%s'\n", user);
    } else {
        printf("No rate limiting data found for user '%s'\n", user);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) usage(argv[0]);

    const char *pin_dir_override = NULL;
    int use_tpm = 0;
    int no_tpm = 0;
    int sso_flag = -1; // -1 ask (interactive only), 0 never, 1 yes
    int cmd_index = 1;
    while (cmd_index < argc) {
        if (strcmp(argv[cmd_index], "--tpm") == 0) {
            use_tpm = 1;
            cmd_index++;
            continue;
        }
        if (strcmp(argv[cmd_index], "--no-tpm") == 0) {
            no_tpm = 1;
            cmd_index++;
            continue;
        }
        if (strcmp(argv[cmd_index], "--sso") == 0) {
            sso_flag = 1;
            cmd_index++;
            continue;
        }
        if (strcmp(argv[cmd_index], "--no-sso") == 0) {
            sso_flag = 0;
            cmd_index++;
            continue;
        }
        if (strcmp(argv[cmd_index], "--pin-dir") == 0) {
            if (cmd_index + 1 >= argc) {
                fprintf(stderr, "--pin-dir requires an absolute directory path\n");
                return 2;
            }
            pin_dir_override = argv[cmd_index + 1];
            cmd_index += 2;
            continue;
        }
        if (strncmp(argv[cmd_index], "--pin-dir=", 10) == 0) {
            pin_dir_override = argv[cmd_index] + 10;
            cmd_index++;
            continue;
        }
        break;
    }

    if (cmd_index >= argc) usage(argv[0]);

    const char *cmd = argv[cmd_index];
    if (strcmp(cmd, "help") == 0) usage(argv[0]);

    if (pin_dir_override && (!*pin_dir_override || *pin_dir_override != '/')) {
        fprintf(stderr, "--pin-dir requires an absolute directory path\n");
        return 2;
    }

    char *user = get_username(argc, argv, cmd_index);
    if (!user) die("No username provided");

    pinlock_config_t config;
    load_config(user, &config);
    if (pin_dir_override) {
        int n = snprintf(config.pin_dir, sizeof(config.pin_dir), "%s", pin_dir_override);
        if (n < 0 || n >= (int)sizeof(config.pin_dir)) {
            fprintf(stderr, "--pin-dir path is too long\n");
            free(user);
            return 2;
        }
    }

    if (!strcmp(cmd, "config")) {
        show_config(user, &config);
        free(user);
        return 0;
    }

    struct passwd *pw = getpwnam(user);
    if (!pw) die("Cannot resolve user");

    char *dir = get_pinlock_dir(user, &config);
    if (!dir) die("Cannot resolve PIN directory");

    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/%s.pin", dir, user);
    if (n < 0 || n >= (int)sizeof(path)) die("Path too long");

    if (!strcmp(cmd, "check")) {
        int issues = show_storage_check(user, dir, path, pw, &config);
        free(user);
        return issues ? 1 : 0;
    }

    if (!strcmp(cmd, "tpm-status")) {
#ifdef HAVE_TPM2
        pinlock_tpm2_da_info_t info;
        if (pinlock_tpm2_da_info(config.tpm2_tcti, &info) != 0) {
            printf("TPM 2.0: not available\n");
        } else {
            printf("TPM 2.0: available\n");
            printf("  Dictionary attack lockout: %s\n",
                   info.in_lockout ? "ACTIVE (PIN auth refused until recovery or admin clear)" : "not active");
            printf("  Failed attempts counted: %u of %u\n", info.lockout_counter, info.max_auth_fail);
            printf("  Counter decrement interval: %u seconds\n", info.lockout_interval);
            printf("  Lockout recovery time: %u seconds\n", info.lockout_recovery);
            if (info.lockout_auth_set)
                printf("  Note: the TPM lockout hierarchy has an auth value set (often by a\n"
                       "  previously installed OS). If it is unknown, the counter cannot be\n"
                       "  cleared manually; it heals on its own, or clear the TPM from the\n"
                       "  firmware setup menu (this orphans all TPM records, re-enroll after).\n");
        }
        if (access(path, F_OK) != 0) {
            printf("PIN record for '%s': none\n", user);
        } else switch (pinlock_record_type_of_file(path)) {
        case PINLOCK_RECORD_TPM2:   printf("PIN record for '%s': TPM-sealed\n", user); break;
        case PINLOCK_RECORD_ARGON2: printf("PIN record for '%s': argon2id hash\n", user); break;
        default:                    printf("PIN record for '%s': unrecognized or unreadable\n", user); break;
        }
        free(user);
        return 0;
#else
        fprintf(stderr, "This build has no TPM support (rebuild with TPM2=1 and tpm2-tss headers)\n");
        free(user);
        return 1;
#endif
    }

    if (!strcmp(cmd, "status")) {
        printf("PIN directory: %s\n", dir);
        int file_status = check_pin_file_security(path, pw, &config, 0);
        if (file_status == 0 && access(path, R_OK)==0) {
            printf("PIN enrolled for %s\n", user);
            switch (pinlock_record_type_of_file(path)) {
            case PINLOCK_RECORD_TPM2:   printf("Storage backend: TPM-sealed record\n"); break;
            case PINLOCK_RECORD_ARGON2: printf("Storage backend: argon2id hash\n"); break;
            default:                    printf("Storage backend: unrecognized\n"); break;
            }

            // Check if user is currently locked out
            char rl_path[1024];
            int rl_n = snprintf(rl_path, sizeof(rl_path), "%s/%s.ratelimit", dir, user);
            if (rl_n < (int)sizeof(rl_path) && access(rl_path, R_OK) == 0) {
                printf("Rate limiting data exists (check logs for lockout status)\n");
            }
        } else if (file_status == 1) {
            printf("PIN storage for %s has unsafe permissions or ownership\n", user);
        } else {
            printf("No PIN set for %s\n", user);
        }
        free(user); 
        return 0;
    }

    if (!strcmp(cmd, "unlock")) {
        unlock_user(user, dir);
        free(user);
        return 0;
    }

    if (!strcmp(cmd, "remove")) {
        unlink(path);  // ignore error
        
        // Also remove rate limiting data
        char rl_path[1024];
        int rl_n = snprintf(rl_path, sizeof(rl_path), "%s/%s.ratelimit", dir, user);
        if (rl_n < (int)sizeof(rl_path)) {
            unlink(rl_path);  // ignore error
        }
        
        printf("PIN and rate limiting data removed for user '%s'\n", user);
        free(user); 
        return 0;
    }

    if (!strcmp(cmd, "change")) {
        if (access(path, F_OK) != 0) {
            fprintf(stderr, "No PIN set for user '%s'\n", user);
            free(user);
            return 1;
        }
        char *cur = prompt_hidden("Current PIN: ");
        if (!cur || !*cur) {
            fprintf(stderr, "No PIN entered.\n");
            free(cur);
            free(user);
            return 1;
        }
        char *sso_secret = NULL;
        int v = pinlock_verify_pin(path, cur, config.tpm2_tcti, &sso_secret);
        memset(cur, 0, strlen(cur));
        free(cur);
        if (v != PINLOCK_VERIFY_OK) {
            switch (v) {
            case PINLOCK_VERIFY_FAIL:
                fprintf(stderr, "Current PIN is incorrect.\n"); break;
            case PINLOCK_VERIFY_LOCKOUT:
                fprintf(stderr, "The TPM is in dictionary attack lockout; try again later.\n"); break;
            case PINLOCK_VERIFY_UNREADABLE:
                fprintf(stderr, "Cannot read the PIN record.\n"); break;
            default:
                fprintf(stderr, "The PIN record needs a TPM that is not usable right now.\n"); break;
            }
            free(user);
            return 1;
        }

        int was_tpm = pinlock_record_type_of_file(path) == PINLOCK_RECORD_TPM2;
        int was_sso = record_is_sso(path);
        int had_secret = sso_secret != NULL;

        char *p1 = prompt_new_pin(&config);
        if (!p1) {
            if (sso_secret) { memset(sso_secret, 0, strlen(sso_secret)); free(sso_secret); }
            free(user);
            return 1;
        }
        char *encoded = make_record(&config, p1, sso_secret, was_tpm);
        if (sso_secret) { memset(sso_secret, 0, strlen(sso_secret)); free(sso_secret); }
        memset(p1, 0, strlen(p1));
        free(p1);
        if (!encoded) {
            free(user);
            return 1;
        }
        if (write_file_restrict(dir, path, encoded, pw, system_pin_dir_enabled(&config)) != 0) die("write pin file");
        free(encoded);
        clear_rate_limit(dir, user);
        printf("PIN changed for user '%s'\n", user);
        if (was_sso && !had_secret)
            printf("Note: the sealed account password could not be recovered; run\n"
                   "'pinlockctl --tpm --sso set %s' to restore wallet unlocking.\n", user);
        free(user);
        return 0;
    }

    if (!strcmp(cmd, "reset")) {
#ifdef HAVE_TPM2
        if (ensure_dir(dir, pw, system_pin_dir_enabled(&config)) != 0) die("Cannot create PIN directory");
        if (check_pin_dir_security(dir, pw, &config, 0) != 0) die("Unsafe PIN directory");

        char *acct = prompt_hidden("Account password: ");
        if (!acct || !*acct || verify_account_password(user, acct) != 0) {
            fprintf(stderr, "That does not match the current account password; nothing was changed.\n");
            if (acct) { memset(acct, 0, strlen(acct)); free(acct); }
            free(user);
            return 1;
        }

        // Keep the previous record's backend and sso choice unless
        // flags say otherwise; a first-time reset defaults to the TPM
        // when one is present.
        int had = access(path, F_OK) == 0;
        int tpm_backend = had ? pinlock_record_type_of_file(path) == PINLOCK_RECORD_TPM2
                              : pinlock_tpm2_available(config.tpm2_tcti);
        if (no_tpm) tpm_backend = 0;
        if (use_tpm) tpm_backend = 1;
        int want_sso = sso_flag == -1 ? (had && record_is_sso(path)) : sso_flag;

        char *p1 = prompt_new_pin(&config);
        if (!p1) {
            memset(acct, 0, strlen(acct));
            free(acct);
            free(user);
            return 1;
        }
        char *encoded = make_record(&config, p1, (want_sso && tpm_backend) ? acct : NULL, tpm_backend);
        memset(p1, 0, strlen(p1));
        free(p1);
        memset(acct, 0, strlen(acct));
        free(acct);
        if (!encoded) {
            free(user);
            return 1;
        }
        if (write_file_restrict(dir, path, encoded, pw, system_pin_dir_enabled(&config)) != 0) die("write pin file");
        free(encoded);
        clear_rate_limit(dir, user);
        printf("PIN reset for user '%s'\n", user);
        free(user);
        return 0;
#else
        fprintf(stderr, "reset needs a build with TPM support; use 'remove' and 'set' instead\n");
        free(user);
        return 1;
#endif
    }

    if (!strcmp(cmd, "enroll") || !strcmp(cmd, "set")) {
        if (ensure_dir(dir, pw, system_pin_dir_enabled(&config)) != 0) die("Cannot create PIN directory");
        if (check_pin_dir_security(dir, pw, &config, 0) != 0) die("Unsafe PIN directory");

#ifdef HAVE_TPM2
        // Recommend TPM sealing when a TPM is present. Interactive
        // sessions only, so piped enrollment keeps its current behavior.
        if (!use_tpm && !no_tpm && isatty(STDIN_FILENO) &&
            pinlock_tpm2_available(config.tpm2_tcti)) {
            fprintf(stderr, "TPM 2.0 detected. Sealing the PIN in the TPM protects it against\n");
            fprintf(stderr, "offline cracking if the PIN file is ever stolen (recommended).\n");
            fprintf(stderr, "Seal the PIN in the TPM? [Y/n] ");
            fflush(stderr);
            char answer[16];
            if (fgets(answer, sizeof(answer), stdin) &&
                answer[0] != 'n' && answer[0] != 'N')
                use_tpm = 1;
        }
#else
        (void)no_tpm;
        (void)sso_flag;
#endif

        char *p1 = prompt_new_pin(&config);
        if (!p1) {
            free(user);
            return 1;
        }

        char *sso_pw = NULL;
#ifdef HAVE_TPM2
        if (use_tpm) {
            int want_sso = sso_flag == 1;
            if (sso_flag == -1 && isatty(STDIN_FILENO)) {
                fprintf(stderr, "Also seal your account password, so PIN sign-in unlocks KWallet\n");
                fprintf(stderr, "and other password-protected secrets? [y/N] ");
                fflush(stderr);
                char answer[16];
                if (fgets(answer, sizeof(answer), stdin) && (answer[0] == 'y' || answer[0] == 'Y'))
                    want_sso = 1;
            }
            if (want_sso) {
                sso_pw = prompt_hidden("Account password: ");
                if (!sso_pw || !*sso_pw || strlen(sso_pw) > PINLOCK_TPM2_MAX_SSO
                        || verify_account_password(user, sso_pw) != 0) {
                    fprintf(stderr, "That does not match the current account password; nothing was changed.\n");
                    if (sso_pw) { memset(sso_pw, 0, strlen(sso_pw)); free(sso_pw); }
                    memset(p1, 0, strlen(p1));
                    free(p1); free(user);
                    return 1;
                }
            }
        }
#endif
        char *encoded = make_record(&config, p1, sso_pw, use_tpm);
        if (sso_pw) { memset(sso_pw, 0, strlen(sso_pw)); free(sso_pw); }
        memset(p1, 0, strlen(p1));
        if (!encoded) {
            free(p1); free(user);
            return 1;
        }

        if (write_file_restrict(dir, path, encoded, pw, system_pin_dir_enabled(&config))!=0) die("write pin file");
        clear_rate_limit(dir, user);

        printf("PIN successfully set for user '%s'\n", user);
        printf("Configuration applied:\n");
        printf("  - Storage: %s\n", use_tpm ? "TPM-sealed record" : "argon2id hash");
        printf("  - Length requirement: %d-%d characters\n", config.min_length, config.max_length);
        printf("  - Digits only: %s\n", config.require_digits_only ? "yes" : "no");
        printf("  - Rate limiting: %d attempts per %d seconds\n", config.max_attempts, config.rate_limit_window);
        printf("  - PIN lockout: %s\n", config.enable_lockout ? "enabled" : "disabled");

        free(p1); free(encoded); free(user);
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    free(user);
    usage(argv[0]);
    return 2;
}

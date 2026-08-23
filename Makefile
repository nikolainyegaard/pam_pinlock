CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC
LDFLAGS = -shared
PAM_LIBS = -lpam -largon2
CTL_LIBS = -largon2

# Optional TPM 2.0 backend. Auto-detected via pkg-config; force with
# TPM2=1 or disable with TPM2=0. libcrypto handles the sso record
# wrapping and is already a dependency of tpm2-tss itself.
TPM2_PCDEPS = tss2-esys tss2-mu tss2-tctildr libcrypto
TPM2 ?= $(shell pkg-config --exists $(TPM2_PCDEPS) 2>/dev/null && echo 1 || echo 0)
ifeq ($(TPM2),1)
    CFLAGS += -DHAVE_TPM2 $(shell pkg-config --cflags $(TPM2_PCDEPS))
    TPM2_LIBS = $(shell pkg-config --libs $(TPM2_PCDEPS))
    TPM2_SRC = pinlock_tpm2.c
    PAM_LIBS += $(TPM2_LIBS)
    CTL_LIBS += $(TPM2_LIBS) -lpam
endif

# Installation directories - auto-detect or use common defaults
PAM_MODULE_DIR := $(shell find /lib* /usr/lib* -name "pam_unix.so" -exec dirname {} \; 2>/dev/null | head -1)
ifeq ($(PAM_MODULE_DIR),)
    PAM_MODULE_DIR := /lib/x86_64-linux-gnu/security
endif

LIBDIR = $(PAM_MODULE_DIR)
BINDIR = /usr/local/bin
CONFDIR = /etc
EXAMPLEDIR = $(CONFDIR)/pinlock/examples

# Targets
all: pam_pinlock.so pinlockctl

pam_pinlock.so: pam_pinlock.c pinlock_record.c pinlock_record.h $(TPM2_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ pam_pinlock.c pinlock_record.c $(TPM2_SRC) $(PAM_LIBS)

pinlockctl: pinlockctl.c pinlock_record.c pinlock_record.h $(TPM2_SRC)
	$(CC) $(CFLAGS) -o $@ pinlockctl.c pinlock_record.c $(TPM2_SRC) $(CTL_LIBS)

install: all
	@echo "Installing to PAM directory: $(LIBDIR)"
	install -m 755 -d $(DESTDIR)$(LIBDIR)
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 755 -d $(DESTDIR)$(EXAMPLEDIR)
	install -m 644 pam_pinlock.so $(DESTDIR)$(LIBDIR)/
	install -m 755 pinlockctl $(DESTDIR)$(BINDIR)/
	install -m 644 examples/pinlock.conf $(DESTDIR)$(EXAMPLEDIR)/pinlock.conf
	@echo ""
	@echo "Installation complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Copy /etc/pinlock/examples/pinlock.conf to /etc/pinlock.conf and edit as needed"
	@echo "   sudo cp /etc/pinlock/examples/pinlock.conf /etc/pinlock.conf"
	@echo "2. Add the PAM module to your PAM configuration:"
	@echo "   Example for /etc/pam.d/common-auth:"
	@echo "   auth    optional    pam_pinlock.so"
	@echo "3. Set up PINs for users with: pinlockctl set username"

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/pam_pinlock.so
	rm -f $(DESTDIR)$(BINDIR)/pinlockctl
	rm -f $(DESTDIR)$(EXAMPLEDIR)/pinlock.conf
	rmdir $(DESTDIR)$(EXAMPLEDIR) 2>/dev/null || true
	rmdir $(DESTDIR)$(CONFDIR)/pinlock 2>/dev/null || true

clean:
	rm -f pam_pinlock.so pinlockctl

test: pinlockctl
	@echo "Testing pinlockctl..."
	./pinlockctl help

.PHONY: all install uninstall clean test

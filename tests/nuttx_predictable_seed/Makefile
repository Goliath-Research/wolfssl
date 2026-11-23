# Build the NuttX port's wolfSSL sources with that port's user_settings.h
# and run the predictability checks.
#
#   make -C tests/nuttx_predictable_seed
#
# The checks fail while the port defines WOLFSSL_GENSEED_FORTEST.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
STUB := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD := $(STUB)/build

CFLAGS := -O2 -Wall -Wno-unused-function -Wno-unused-variable -Wno-cpp \
	-DWOLFSSL_USER_SETTINGS \
	-I$(STUB) \
	-I$(ROOT)/RTOS/nuttx/wolfssl \
	-I$(ROOT)

SRCS := \
	src/crl.c \
	src/internal.c \
	src/keys.c \
	src/ocsp.c \
	src/sniffer.c \
	src/ssl.c \
	src/tls.c \
	src/tls13.c \
	src/wolfio.c \
	wolfcrypt/src/aes.c \
	wolfcrypt/src/cmac.c \
	wolfcrypt/src/des3.c \
	wolfcrypt/src/dh.c \
	wolfcrypt/src/ecc.c \
	wolfcrypt/src/hmac.c \
	wolfcrypt/src/random.c \
	wolfcrypt/src/rsa.c \
	wolfcrypt/src/sha.c \
	wolfcrypt/src/sha256.c \
	wolfcrypt/src/sha512.c \
	wolfcrypt/src/sha3.c \
	wolfcrypt/src/asm.c \
	wolfcrypt/src/asn.c \
	wolfcrypt/src/blake2s.c \
	wolfcrypt/src/chacha.c \
	wolfcrypt/src/chacha20_poly1305.c \
	wolfcrypt/src/coding.c \
	wolfcrypt/src/compress.c \
	wolfcrypt/src/cpuid.c \
	wolfcrypt/src/cryptocb.c \
	wolfcrypt/src/curve25519.c \
	wolfcrypt/src/curve448.c \
	wolfcrypt/src/ecc_fp.c \
	wolfcrypt/src/eccsi.c \
	wolfcrypt/src/ed25519.c \
	wolfcrypt/src/ed448.c \
	wolfcrypt/src/error.c \
	wolfcrypt/src/fe_448.c \
	wolfcrypt/src/fe_low_mem.c \
	wolfcrypt/src/fe_operations.c \
	wolfcrypt/src/ge_448.c \
	wolfcrypt/src/ge_low_mem.c \
	wolfcrypt/src/ge_operations.c \
	wolfcrypt/src/hash.c \
	wolfcrypt/src/kdf.c \
	wolfcrypt/src/integer.c \
	wolfcrypt/src/logging.c \
	wolfcrypt/src/md5.c \
	wolfcrypt/src/memory.c \
	wolfcrypt/src/pkcs12.c \
	wolfcrypt/src/pkcs7.c \
	wolfcrypt/src/poly1305.c \
	wolfcrypt/src/pwdbased.c \
	wolfcrypt/src/rc2.c \
	wolfcrypt/src/sakke.c \
	wolfcrypt/src/signature.c \
	wolfcrypt/src/srp.c \
	wolfcrypt/src/sp_arm32.c \
	wolfcrypt/src/sp_arm64.c \
	wolfcrypt/src/sp_armthumb.c \
	wolfcrypt/src/sp_c32.c \
	wolfcrypt/src/sp_c64.c \
	wolfcrypt/src/sp_cortexm.c \
	wolfcrypt/src/sp_dsp32.c \
	wolfcrypt/src/sp_int.c \
	wolfcrypt/src/sp_x86_64.c \
	wolfcrypt/src/tfm.c \
	wolfcrypt/src/wc_dsp.c \
	wolfcrypt/src/wc_encrypt.c \
	wolfcrypt/src/wc_pkcs11.c \
	wolfcrypt/src/wc_port.c \
	wolfcrypt/src/wolfevent.c \
	wolfcrypt/src/wolfmath.c

OBJS := $(patsubst %.c,$(BUILD)/%.o,$(SRCS))

.PHONY: all clean test

all: test

$(BUILD)/test_nuttx_genseed: $(OBJS) $(BUILD)/test_nuttx_genseed.o
	$(CC) -o $@ $^ -lm

$(BUILD)/test_nuttx_genseed.o: $(STUB)/test_nuttx_genseed.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/%.o: $(ROOT)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(BUILD)/test_nuttx_genseed
	$(BUILD)/test_nuttx_genseed

clean:
	rm -rf $(BUILD)

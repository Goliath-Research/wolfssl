# Build and run from the wolfSSL tree:
#   make -C tests/espressif/client_tls_log_overread
#
# full must fail while client-tls.c logs a 256-byte wolfSSL_read with %s.
# short must pass. After the read is capped and terminated, both pass.

REPO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../../..)
WOLFSSL_PREFIX ?= /tmp/wolfssl-inst
CLIENT := $(REPO_ROOT)/IDE/Espressif/ESP-IDF/examples/wolfssl_client/main/client-tls.c
CLIENT_INC := $(REPO_ROOT)/IDE/Espressif/ESP-IDF/examples/wolfssl_client/main/include

CC := gcc
CFLAGS := -Wall -Wextra -Wno-unused-parameter -g -O1 -fno-omit-frame-pointer \
	-fsanitize=address -pthread \
	-DWOLFSSL_USE_OPTIONS_H -DESP_IDF_VERSION_MAJOR=5 \
	-include cert_macros.h \
	-DCONFIG_WOLFSSL_TARGET_HOST=\"127.0.0.1\" \
	-DCONFIG_WOLFSSL_TARGET_PORT=18111 \
	-I$(WOLFSSL_PREFIX)/include \
	-Istubs \
	-I$(CLIENT_INC) \
	-I.
LDFLAGS := -fsanitize=address -pthread -L$(WOLFSSL_PREFIX)/lib -Wl,-rpath,$(WOLFSSL_PREFIX)/lib -lwolfssl

.PHONY: all test test-short test-full clean
all: test

build/client_tls_log_overread: driver.c log_walk.c $(CLIENT)
	mkdir -p build
	$(CC) $(CFLAGS) -o $@ driver.c log_walk.c $(CLIENT) $(LDFLAGS)

export ASAN_OPTIONS := detect_leaks=0:halt_on_error=1:abort_on_error=1

test-short: build/client_tls_log_overread
	ASAN_OPTIONS=$(ASAN_OPTIONS) ./build/client_tls_log_overread short

test-full: build/client_tls_log_overread
	ASAN_OPTIONS=$(ASAN_OPTIONS) ./build/client_tls_log_overread full

test: test-short test-full

clean:
	rm -rf build

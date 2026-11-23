# Build and run the Renesas rcvBuff terminator tests.
#
# These tests are expected to FAIL while the samples pass BUFF_SIZE to
# wolfSSL_read / tcp_rcv_dat and then store a NUL at that index. A 256-byte
# payload makes that store one byte past the array. AddressSanitizer aborts
# the client. After the read length is kept inside the array, the same
# commands exit 0.
#
# From the repository root. HAVE_GETRANDOM is required with
# WOLFSSL_FILESYSTEM=no so the library can seed its RNG on Linux; the
# samples themselves are built with NO_FILESYSTEM.
#   cmake -B /tmp/wolfssl-build -DWOLFSSL_FILESYSTEM=no -DWOLFSSL_EXAMPLES=no \
#       -DWOLFSSL_CRYPT_TESTS=no -DCMAKE_C_FLAGS="-DHAVE_GETRANDOM"
#   cmake --build /tmp/wolfssl-build -j"$(nproc)"
#   make -C tests/renesas_rcvbuff WOLFSSL_BUILD=/tmp/wolfssl-build test

ROOT := ../..
WOLFSSL_BUILD ?= /tmp/wolfssl-build
OUT := /tmp/renesas-rcvbuff-tests

CC := gcc
SAN := -fsanitize=address -fno-omit-frame-pointer -g -O1
INC := -I$(WOLFSSL_BUILD) -I$(ROOT) -Istubs
CFLAGS := $(SAN) $(INC) -DWOLFSSL_USE_OPTIONS_H -DUSE_CERT_BUFFERS_2048 -Wno-macro-redefined
LIBS := -L$(WOLFSSL_BUILD) -lwolfssl -Wl,-rpath,$(WOLFSSL_BUILD) -pthread

T4_DIR := $(ROOT)/IDE/Renesas/cs+/Projects/t4_demo
PROJECTS_DIR := $(ROOT)/IDE/Renesas/e2studio/Projects/test/src
GR_DIR := $(ROOT)/IDE/Renesas/e2studio/RX65N/GR-ROSE/test/src
RX_DIR := $(ROOT)/IDE/Renesas/e2studio/RX72N/EnvisionKit/Simple/test/src
RA_DIR := $(ROOT)/IDE/Renesas/e2studio/RA6M4
RZN_DIR := $(ROOT)/IDE/Renesas/e2studio/RZN2L

.PHONY: all test clean

all: $(OUT)/payload_server $(OUT)/tcp_payload_server \
	$(OUT)/client_t4 $(OUT)/client_projects $(OUT)/client_grrose \
	$(OUT)/client_rx72n_tls $(OUT)/client_rx72n_tcp \
	$(OUT)/client_ra6m4 $(OUT)/client_rzn2l

$(OUT):
	mkdir -p $(OUT)

$(OUT)/payload_server: payload_server.c | $(OUT)
	$(CC) $(CFLAGS) -o $@ payload_server.c $(LIBS)

$(OUT)/tcp_payload_server: tcp_payload_server.c | $(OUT)
	$(CC) $(SAN) -o $@ tcp_payload_server.c

$(OUT)/client_t4: harness_t4.c platform_t4.c $(T4_DIR)/wolf_client.c | $(OUT)
	$(CC) $(CFLAGS) -I$(T4_DIR) -o $@ harness_t4.c platform_t4.c $(T4_DIR)/wolf_client.c $(LIBS)

$(OUT)/client_projects: harness_projects.c platform_t4.c $(PROJECTS_DIR)/wolf_client.c | $(OUT)
	$(CC) $(CFLAGS) -I$(PROJECTS_DIR) -o $@ harness_projects.c platform_t4.c $(PROJECTS_DIR)/wolf_client.c $(LIBS)

$(OUT)/client_grrose: harness_grrose.c platform_t4.c $(GR_DIR)/wolf_client.c | $(OUT)
	$(CC) $(CFLAGS) -I$(GR_DIR) -o $@ harness_grrose.c platform_t4.c $(GR_DIR)/wolf_client.c $(LIBS)

$(OUT)/client_rx72n_tls: harness_rx72n_tls.c platform_t4.c $(RX_DIR)/client/simple_tls_tsip_client.c | $(OUT)
	$(CC) $(CFLAGS) -DSIMPLE_TLS_CLIENT -include stubs/skip_simple_demo.h \
		-I$(RX_DIR) -I$(ROOT)/IDE/Renesas/e2studio/RX72N/EnvisionKit/wolfssl_demo \
		-o $@ harness_rx72n_tls.c platform_t4.c $(RX_DIR)/client/simple_tls_tsip_client.c $(LIBS)

$(OUT)/client_rx72n_tcp: harness_rx72n_tcp.c platform_t4.c $(RX_DIR)/client/simple_tcp_client.c | $(OUT)
	$(CC) $(CFLAGS) -I$(RX_DIR) -o $@ harness_rx72n_tcp.c platform_t4.c $(RX_DIR)/client/simple_tcp_client.c $(LIBS)

$(OUT)/client_ra6m4: harness_ra6m4.c platform_freertos.c $(RA_DIR)/test/src/wolf_client.c | $(OUT)
	$(CC) $(CFLAGS) -I$(RA_DIR)/common -o $@ harness_ra6m4.c platform_freertos.c $(RA_DIR)/test/src/wolf_client.c $(LIBS)

$(OUT)/client_rzn2l: harness_rzn2l.c platform_freertos.c $(RZN_DIR)/test/src/test/wolf_client.c | $(OUT)
	$(CC) $(CFLAGS) -DTLS_CLIENT -I$(RZN_DIR)/common -o $@ harness_rzn2l.c platform_freertos.c $(RZN_DIR)/test/src/test/wolf_client.c $(LIBS)

test: all
	WOLFSSL_BUILD=$(WOLFSSL_BUILD) OUT=$(OUT) ./run_tests.sh

clean:
	rm -rf $(OUT)

# These tests fail until unreaped HMAC and SHA-3 descriptor states are bounded.
REPO_ROOT := ../..
CC ?= gcc
CFLAGS := -std=gnu11 -O1 -g -Wall -Wextra -Wno-unused-function \
	-Wno-unused-parameter -Wno-override-init \
	-I$(REPO_ROOT) -Iinclude -DWOLFSSL_USE_OPTIONS_H
LDFLAGS := -L$(REPO_ROOT)/src/.libs -lwolfssl -lpthread -lm

.PHONY: test clean
test: hmac_unreaped_state_test
	./hmac_unreaped_state_test

hmac_unreaped_state_test: hmac_unreaped_state_test.c \
		$(REPO_ROOT)/linuxkm/lkcapi_sha_glue.c \
		$(REPO_ROOT)/src/.libs/libwolfssl.a
	$(CC) $(CFLAGS) -o $@ hmac_unreaped_state_test.c $(LDFLAGS)

clean:
	rm -f hmac_unreaped_state_test

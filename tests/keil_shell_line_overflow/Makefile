# Host build of the Keil shell line reader. The cases fail until both
# wolfssl_fgets copies stop at num-1 and both getline copies ignore a
# trailing ampersand unless the line is at least two characters.
CC := gcc
STUBS := $(CURDIR)/stubs
MDK5 := ../../IDE/MDK5-ARM/Projects/wolfSSL-Full
MDKARM := ../../IDE/MDK-ARM/MDK-ARM/wolfSSL
CFLAGS := -std=c99 -Wall -Wno-unused-function -Wno-unused-variable \
	-Wno-unused-but-set-variable -Wno-missing-braces -g -O1 -fno-builtin \
	-I$(STUBS) -I$(CURDIR)

.PHONY: test clean

test: test_mdk5 test_mdk_arm
	./test_mdk5; status=$$?; \
	./test_mdk_arm; status2=$$?; \
	test $$status -eq 0 -a $$status2 -eq 0

test_mdk5: test_mdk5.c console_feed.h test_cases.h $(MDK5)/shell.c
	$(CC) $(CFLAGS) -fsanitize=address -I$(MDK5) -o $@ test_mdk5.c

test_mdk_arm: test_mdk_arm.c console_feed.h test_cases.h \
		$(MDKARM)/shell.c $(MDKARM)/wolfssl_MDK_ARM.c
	$(CC) $(CFLAGS) -fsanitize=address -I$(MDKARM) -o $@ test_mdk_arm.c

clean:
	rm -f test_mdk5 test_mdk_arm

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "console_feed.h"

#undef getchar
#undef putchar
#define getchar() test_getchar()
#define putchar(c) test_putchar(c)

void osThreadYield(void) {}
void osDelay(unsigned long t) { (void)t; }
void os_tsk_delete_self(void) {}

#define TEST_FN(name) void name(void *args) { (void)args; }
TEST_FN(echoclient_test)
TEST_FN(echoserver_test)
TEST_FN(benchmark_test)
TEST_FN(wolfcrypt_test)
TEST_FN(client_test)
TEST_FN(server_test)
TEST_FN(kill_task)
TEST_FN(md5_test)
TEST_FN(md4_test)
TEST_FN(sha_test)
TEST_FN(sha256_test)
TEST_FN(hmac_md5_test)
TEST_FN(hmac_sha_test)
TEST_FN(hmac_sha256_test)
TEST_FN(arc4_test)
TEST_FN(des_test)
TEST_FN(des3_test)
TEST_FN(aes_test)
TEST_FN(random_test)
TEST_FN(rsa_test)
TEST_FN(dh_test)
TEST_FN(dsa_test)
TEST_FN(pwdbased_test)

/* Drop static/extern so the shell's getline can be called from this test,
 * and so a static definition may follow the earlier extern declaration. */
#define static
#define extern
#define getline shell_getline
#include "shell.c"
#undef getline
#undef static
#undef extern

#include "test_cases.h"

int main(void)
{
    return run_shell_cases("MDK5 shell");
}

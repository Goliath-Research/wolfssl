#include <wolfssl/ssl.h>
#include "wolf_demo.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    WOLFSSL_CTX *ctx;
    func_args args;
    char *argv[] = { "client", "127.0.0.1", "11111", NULL };

    ctx = wolfSSL_TLS_client_init();
    if (ctx == NULL) {
        fprintf(stderr, "client init failed\n");
        return 1;
    }
    memset(&args, 0, sizeof(args));
    args.argc = 3;
    args.argv = argv;
    wolfSSL_TLS_client(ctx, &args);
    return 0;
}

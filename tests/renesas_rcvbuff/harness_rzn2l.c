#include "wolfssl_demo.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    TestInfo info;
    int ret;

    memset(&info, 0, sizeof(info));
    info.id = 1;
    info.port = 11111;
    snprintf(info.name, sizeof(info.name), "rzn2l");
    info.cipher = NULL;

    wolfSSL_TLS_client_init();
    info.ctx = client_ctx;
    if (info.ctx == NULL) {
        fprintf(stderr, "client init failed\n");
        return 1;
    }
    ret = wolfSSL_TLS_client_do(&info);
    return (ret < 0) ? 1 : 0;
}

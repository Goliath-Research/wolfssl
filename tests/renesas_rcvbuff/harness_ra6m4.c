#include "wolfssl_demo.h"

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

uint8_t g_ether0_mac_address[6];

int SEGGER_RTT_vprintf(unsigned BufferIndex, const char *sFormat,
    va_list *pParamList)
{
    (void)BufferIndex;
    return vprintf(sFormat, *pParamList);
}

int main(void)
{
    TestInfo info;
    int ret;

    memset(&info, 0, sizeof(info));
    info.id = 1;
    info.port = 11111;
    snprintf(info.name, sizeof(info.name), "ra6m4");
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

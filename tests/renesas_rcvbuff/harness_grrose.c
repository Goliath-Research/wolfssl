#include "wolfssl_demo.h"

#include <stdio.h>

int main(void)
{
    wolfSSL_TLS_client_init(NULL);
    wolfSSL_TLS_client();
    return 0;
}

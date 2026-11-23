#include <stdio.h>

void wolfSSL_TLS_client_init(const char *cipherlist);
void wolfSSL_TLS_client(void);

int main(void)
{
    wolfSSL_TLS_client_init(NULL);
    wolfSSL_TLS_client();
    return 0;
}

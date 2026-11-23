/* TLS peer for the Renesas sample clients.
 * trusted: certificate and key named server_cert_der_2048 / server_key_der_2048
 *          in wolfssl/certs_test.h (signed by the CA the samples load).
 * untrusted: certificate and key named client_cert_der_2048 / client_key_der_2048
 *            in the same header, which is not signed by that CA.
 * The private key bytes stay in that header; this file only names the symbols.
 */
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int load_identity(WOLFSSL_CTX *ctx, int trusted)
{
    const unsigned char *cert;
    const unsigned char *key;
    long cert_sz;
    long key_sz;

    if (trusted) {
        cert = server_cert_der_2048;
        cert_sz = (long)sizeof_server_cert_der_2048;
        key = server_key_der_2048;
        key_sz = (long)sizeof_server_key_der_2048;
    }
    else {
        cert = client_cert_der_2048;
        cert_sz = (long)sizeof_client_cert_der_2048;
        key = client_key_der_2048;
        key_sz = (long)sizeof_client_key_der_2048;
    }

    if (wolfSSL_CTX_use_certificate_buffer(ctx, cert, cert_sz,
            WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "SERVER cert load failed\n");
        return -1;
    }
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, key, key_sz,
            WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "SERVER key load failed\n");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int trusted;
    int nbytes;
    int port;
    int listen_fd = -1;
    int conn = -1;
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    struct sockaddr_in addr;
    unsigned char payload[256];
    unsigned char inbuf[256];
    int opt = 1;
    int wrote;

    if (argc != 4) {
        fprintf(stderr, "usage: payload_server trusted|untrusted nbytes port\n");
        return 2;
    }
    trusted = (strcmp(argv[1], "trusted") == 0);
    if (!trusted && strcmp(argv[1], "untrusted") != 0) {
        fprintf(stderr, "mode must be trusted or untrusted\n");
        return 2;
    }
    nbytes = atoi(argv[2]);
    port = atoi(argv[3]);
    if (nbytes < 1 || nbytes > (int)sizeof(payload) || port <= 0) {
        fprintf(stderr, "bad nbytes or port\n");
        return 2;
    }

    memset(payload, (nbytes == 4) ? 'p' : 'A', (size_t)nbytes);
    if (nbytes == 4) {
        memcpy(payload, "pong", 4);
    }

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed\n");
        return 1;
    }
    ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
    if (ctx == NULL || load_identity(ctx, trusted) != 0) {
        fprintf(stderr, "server ctx failed\n");
        return 1;
    }

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }
    (void)setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        return 1;
    }
    if (listen(listen_fd, 1) != 0) {
        perror("listen");
        return 1;
    }
    fprintf(stderr, "SERVER_READY\n");
    fflush(stderr);

    conn = accept(listen_fd, NULL, NULL);
    if (conn < 0) {
        perror("accept");
        return 1;
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "wolfSSL_new failed\n");
        return 1;
    }
    if (wolfSSL_set_fd(ssl, conn) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_set_fd failed\n");
        return 1;
    }
    if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "SERVER_HANDSHAKE_FAIL %d\n", wolfSSL_get_error(ssl, 0));
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(conn);
        close(listen_fd);
        wolfSSL_Cleanup();
        return 0;
    }

    /* The sample writes "Hello Server\n" before it reads. Read that first
     * so the two sides cannot block on each other's application data. */
    (void)wolfSSL_read(ssl, inbuf, (int)sizeof(inbuf));

    wrote = wolfSSL_write(ssl, payload, nbytes);
    fprintf(stderr, "SERVER_WROTE %d\n", wrote);
    fflush(stderr);
    if (wrote != nbytes) {
        fprintf(stderr, "SERVER_WRITE_FAIL %d\n", wolfSSL_get_error(ssl, wrote));
        return 1;
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    close(conn);
    close(listen_fd);
    wolfSSL_Cleanup();
    return 0;
}

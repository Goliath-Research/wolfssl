/* Spec for the INtime sample client receive-buffer print.
 *
 * wolfExample_TLSClient clears a 4096-byte stack buffer, reads application
 * data into all of it, and passes that buffer to printf as a C string.
 * This test is the hostile peer: after a TLS 1.2 handshake that the sample
 * accepts with its embedded test CA, it writes 4096 non-zero application
 * bytes. The test fails while that printf argument has no terminator inside
 * the buffer, and passes once a terminator is stored within the buffer
 * before the print.
 *
 * The INtime server in the same file reads sizeof(buff)-1 after zeroing the
 * buffer, so it does not share this bug and is not asserted here.
 * IDE/Espressif/ESP-IDF/examples/wolfssl_client/main/client-tls.c prints a
 * full-size wolfSSL_read the same way and is left untested.
 */

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

/* Must match TLS_MAXDATASIZE in IDE/INTIME-RTOS/wolfExamples.c. */
#define RCV_BUFSZ 4096
#define PAYLOAD_BYTE 0x41

extern int wolfExample_TLSClient(const char *ip, int port);

/* Linked because the sample translation unit references them. The client
 * path under test does not call them. */
int wolfcrypt_test(void *args)
{
    (void)args;
    return 0;
}

int benchmark_test(void *args)
{
    (void)args;
    return 0;
}

int __real_printf(const char *fmt, ...);

static int g_saw_received;
static int g_has_nul_within_buffer;
static int g_payload_is_server_bytes;
static int g_terminated_len;

int __wrap_printf(const char *fmt, ...)
{
    va_list ap;
    int n;

    if (fmt != NULL && strcmp(fmt, "Received: \t%s\n") == 0) {
        char *s;
        const char *nul;

        va_start(ap, fmt);
        s = va_arg(ap, char *);
        va_end(ap);

        g_saw_received = 1;
        nul = (const char *)memchr(s, '\0', RCV_BUFSZ);
        if (nul == NULL) {
            int i;

            g_has_nul_within_buffer = 0;
            g_payload_is_server_bytes = 1;
            for (i = 0; i < RCV_BUFSZ; i++) {
                if ((unsigned char)s[i] != PAYLOAD_BYTE) {
                    g_payload_is_server_bytes = 0;
                    break;
                }
            }
            /* Real printf %s. glibc takes this to strlen, which reads past
             * the object when no NUL sits inside it. stdout is /dev/null. */
            return __real_printf(fmt, s);
        }

        g_has_nul_within_buffer = 1;
        g_terminated_len = (int)(nul - s);
        g_payload_is_server_bytes = g_terminated_len > 0;
        {
            int i;
            for (i = 0; i < g_terminated_len; i++) {
                if ((unsigned char)s[i] != PAYLOAD_BYTE) {
                    g_payload_is_server_bytes = 0;
                    break;
                }
            }
        }
        return __real_printf(fmt, s);
    }

    va_start(ap, fmt);
    n = vfprintf(stdout, fmt, ap);
    va_end(ap);
    return n;
}

struct peer_ctx {
    int listen_fd;
    int write_rc;
};

static void *peer_thread(void *arg)
{
    struct peer_ctx *ctx = (struct peer_ctx *)arg;
    int cfd = -1;
    WOLFSSL_CTX *sslCtx = NULL;
    WOLFSSL *ssl = NULL;
    unsigned char payload[RCV_BUFSZ];
    unsigned char inbuf[64];
    int off;
    int n;

    cfd = accept(ctx->listen_fd, NULL, NULL);
    if (cfd < 0) {
        ctx->write_rc = -1;
        return NULL;
    }

    sslCtx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
    if (sslCtx == NULL) {
        ctx->write_rc = -2;
        goto done;
    }
    if (wolfSSL_CTX_use_certificate_buffer(sslCtx, server_cert_der_2048,
            (long)sizeof_server_cert_der_2048, SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        ctx->write_rc = -3;
        goto done;
    }
    if (wolfSSL_CTX_use_PrivateKey_buffer(sslCtx, server_key_der_2048,
            (long)sizeof_server_key_der_2048, SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        ctx->write_rc = -4;
        goto done;
    }

    ssl = wolfSSL_new(sslCtx);
    if (ssl == NULL) {
        ctx->write_rc = -5;
        goto done;
    }
    wolfSSL_set_fd(ssl, cfd);
    if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
        ctx->write_rc = -6;
        goto done;
    }

    /* The sample writes the operator line before it reads. Consume it so
     * the client's write cannot stall, then send the full-buffer payload. */
    n = wolfSSL_read(ssl, inbuf, (int)sizeof(inbuf));
    if (n <= 0) {
        ctx->write_rc = -7;
        goto done;
    }

    memset(payload, PAYLOAD_BYTE, sizeof(payload));
    off = 0;
    while (off < RCV_BUFSZ) {
        n = wolfSSL_write(ssl, payload + off, RCV_BUFSZ - off);
        if (n <= 0) {
            ctx->write_rc = -8;
            goto done;
        }
        off += n;
    }
    ctx->write_rc = off;

    /* Stay up until the client closes so the record is not aborted first. */
    wolfSSL_shutdown(ssl);

done:
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(sslCtx);
    if (cfd >= 0)
        close(cfd);
    return NULL;
}

static int listen_local(int *port_out)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t len;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 1) < 0) {
        close(fd);
        return -1;
    }
    len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) < 0) {
        close(fd);
        return -1;
    }
    *port_out = (int)ntohs(addr.sin_port);
    return fd;
}

static int feed_stdin(void)
{
    int p[2];
    const char line[] = "ping\n";

    if (pipe(p) < 0)
        return -1;
    if (write(p[1], line, sizeof(line) - 1) != (ssize_t)(sizeof(line) - 1))
        return -1;
    close(p[1]);
    if (dup2(p[0], STDIN_FILENO) < 0)
        return -1;
    if (p[0] != STDIN_FILENO)
        close(p[0]);
    return 0;
}

int main(void)
{
    struct peer_ctx ctx;
    pthread_t thr;
    int port = 0;
    int devnull;
    int client_rc;
    int join_rc;

    if (wolfSSL_Init() != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed\n");
        return 2;
    }
    if (feed_stdin() != 0) {
        fprintf(stderr, "stdin setup failed: %s\n", strerror(errno));
        return 2;
    }

    devnull = open("/dev/null", O_WRONLY);
    if (devnull < 0 || dup2(devnull, STDOUT_FILENO) < 0) {
        fprintf(stderr, "stdout redirect failed\n");
        return 2;
    }
    if (devnull != STDOUT_FILENO)
        close(devnull);

    memset(&ctx, 0, sizeof(ctx));
    ctx.listen_fd = listen_local(&port);
    if (ctx.listen_fd < 0) {
        fprintf(stderr, "listen failed\n");
        return 2;
    }
    if (pthread_create(&thr, NULL, peer_thread, &ctx) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        return 2;
    }

    alarm(20);
    client_rc = wolfExample_TLSClient("127.0.0.1", port);
    alarm(0);

    close(ctx.listen_fd);
    join_rc = pthread_join(thr, NULL);
    wolfSSL_Cleanup();

    if (join_rc != 0) {
        fprintf(stderr, "pthread_join failed\n");
        return 2;
    }
    if (!g_saw_received) {
        fprintf(stderr,
            "client never printed the response (client_rc=%d peer_rc=%d)\n",
            client_rc, ctx.write_rc);
        return 2;
    }
    if (!g_payload_is_server_bytes) {
        fprintf(stderr, "printed buffer is not the peer payload\n");
        return 2;
    }
    if (!g_has_nul_within_buffer) {
        fprintf(stderr,
            "receive buffer passed to printf has no NUL within %d bytes\n",
            RCV_BUFSZ);
        return 1;
    }
    if (g_terminated_len <= 0 || g_terminated_len >= RCV_BUFSZ) {
        fprintf(stderr, "terminator not inside the receive buffer\n");
        return 1;
    }

    fprintf(stderr, "terminator inside receive buffer at offset %d\n",
        g_terminated_len);
    return 0;
}

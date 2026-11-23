/* Drives tls_smp_client_task() from the Espressif sample against a peer
 * that sends application data. The sample's own wolfSSL_read and the
 * following ESP_LOGI of that buffer are what this exercises.
 *
 * full: 256 non-zero application bytes. The log must stop inside the
 *       256-byte stack buffer (strlen == 255 after the fix: read at most
 *       one byte less, then terminate at the returned length).
 * short: a short reply still has to be logged unchanged.
 */
#include "log_walk.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define USE_CERT_BUFFERS_2048
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

#include "client-tls.h"

#define TEST_PORT 18111
#define FULL_LEN 256

extern void tls_smp_client_task(void *args);

jmp_buf tls_task_return;

void vTaskDelete(void *task)
{
    (void)task;
    longjmp(tls_task_return, 1);
}

int xTaskCreate(void (*fn)(void *), const char *name, unsigned stack,
                void *arg, int prio, TaskHandle_t *out)
{
    (void)fn;
    (void)name;
    (void)stack;
    (void)arg;
    (void)prio;
    (void)out;
    return 0;
}

static int g_full;
static int g_listen_fd = -1;

static int io_retry(WOLFSSL *ssl, int n)
{
    int err;

    if (n > 0) {
        return 0;
    }
    err = wolfSSL_get_error(ssl, n);
    return err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE;
}

static void *peer_thread(void *arg)
{
    unsigned char payload[FULL_LEN];
    unsigned char sink[512];
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    int fd = -1;
    int n;
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    struct timeval tv;

    (void)arg;
    memset(payload, 0, sizeof(payload));
    if (g_full) {
        memset(payload, 0xA5, FULL_LEN);
    }
    else {
        memcpy(payload, "pong", 4);
    }

    tv.tv_sec = 2;
    tv.tv_usec = 0;
    fd = accept(g_listen_fd, (struct sockaddr *)&peer, &peer_len);
    if (fd < 0) {
        perror("accept");
        return NULL;
    }
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
    if (ctx == NULL) {
        fprintf(stderr, "peer: wolfSSL_CTX_new failed\n");
        goto done;
    }
    if (wolfSSL_CTX_use_certificate_buffer(ctx, server_cert_der_2048,
            (long)sizeof_server_cert_der_2048, WOLFSSL_FILETYPE_ASN1)
            != WOLFSSL_SUCCESS) {
        fprintf(stderr, "peer: server certificate rejected\n");
        goto done;
    }
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, server_key_der_2048,
            (long)sizeof_server_key_der_2048, WOLFSSL_FILETYPE_ASN1)
            != WOLFSSL_SUCCESS) {
        fprintf(stderr, "peer: server key rejected\n");
        goto done;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "peer: wolfSSL_new failed\n");
        goto done;
    }
    wolfSSL_set_fd(ssl, fd);
    do {
        n = wolfSSL_accept(ssl);
    } while (io_retry(ssl, n));
    if (n != WOLFSSL_SUCCESS) {
        fprintf(stderr, "peer: wolfSSL_accept %d\n", wolfSSL_get_error(ssl, n));
        goto done;
    }

    do {
        n = wolfSSL_read(ssl, sink, (int)sizeof(sink));
    } while (io_retry(ssl, n));
    if (n <= 0) {
        fprintf(stderr, "peer: wolfSSL_read %d\n", wolfSSL_get_error(ssl, n));
        goto done;
    }

    do {
        n = wolfSSL_write(ssl, payload, g_full ? FULL_LEN : 4);
    } while (io_retry(ssl, n));
    if (n != (g_full ? FULL_LEN : 4)) {
        fprintf(stderr, "peer: wolfSSL_write %d\n", n);
        goto done;
    }
    /* The record is on the socket. Close so this thread does not sit in
     * wolfSSL_read while the client task longjmps out of the log. */

done:
    if (ssl != NULL) {
        wolfSSL_free(ssl);
    }
    if (ctx != NULL) {
        wolfSSL_CTX_free(ctx);
    }
    if (fd >= 0) {
        close(fd);
    }
    return NULL;
}

static int listen_on_port(void)
{
    struct sockaddr_in addr;
    int fd;
    int on = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TEST_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 1) != 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

static int expect_response(size_t want, int fill)
{
    size_t i;

    if (!g_server_response_logged) {
        fprintf(stderr, "Server response was not logged\n");
        return 2;
    }
    if (g_server_response_strlen != want) {
        fprintf(stderr,
                "log walked %zu bytes; a terminated buffer holds %zu\n",
                g_server_response_strlen, want);
        return 1;
    }
    for (i = 0; i < want; i++) {
        unsigned char got = g_server_response_bytes[i];
        unsigned char exp = fill ? (unsigned char)0xA5 : (unsigned char)"pong"[i];

        if (got != exp) {
            fprintf(stderr, "logged byte %zu is 0x%02x, payload byte is 0x%02x\n",
                    i, got, exp);
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    pthread_t thread;
    int rc;

    if (argc != 2 || (strcmp(argv[1], "full") != 0 && strcmp(argv[1], "short") != 0)) {
        fprintf(stderr, "usage: %s full|short\n", argv[0]);
        return 2;
    }
    g_full = strcmp(argv[1], "full") == 0;
    log_walk_reset();

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed\n");
        return 2;
    }
    g_listen_fd = listen_on_port();
    if (g_listen_fd < 0) {
        return 2;
    }
    if (pthread_create(&thread, NULL, peer_thread, NULL) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        return 2;
    }

    alarm(12);
    if (setjmp(tls_task_return) == 0) {
        tls_smp_client_task(NULL);
    }
    alarm(0);

    pthread_join(thread, NULL);
    close(g_listen_fd);
    wolfSSL_Cleanup();

    if (g_full) {
        rc = expect_response(255, 1);
    }
    else {
        rc = expect_response(4, 0);
    }
    if (rc == 0) {
        printf("%s: logged response stayed inside the buffer\n", argv[1]);
    }
    return rc;
}

/* Spec tests for RFC 7250 certificate-type negotiation.
 *
 * A client that offers only a raw public key must abort when the peer selects
 * a normal X.509 certificate, or when the peer omits the selection and the
 * stack would otherwise default to X.509. The same rejection applies to the
 * client certificate type the server selects. These tests fail while that
 * check is missing: the handshake completes and the pinned raw key is never
 * consulted.
 *
 * Build and run from the repository root, against a tree configured with
 * --enable-rpk (TLS 1.3 enabled, the default):
 *
 *   ./autogen.sh && ./configure --enable-rpk --disable-examples
 *   make -j
 *   gcc -o tests/api/test_rpk_cert_type_downgrade \
 *       tests/api/test_rpk_cert_type_downgrade.c \
 *       -I. src/.libs/libwolfssl.a -lpthread -lm
 *   ./tests/api/test_rpk_cert_type_downgrade
 *
 * Exit status is 0 only when every unoffered type is rejected and the honest
 * handshakes still complete. On an unfixed tree the rejection cases complete
 * the handshake and this program exits non-zero.
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IO_CAP (256 * 1024)

#define CA_FILE  "certs/ca-cert.pem"
#define SVR_CERT "certs/server-cert.pem"
#define SVR_KEY  "certs/server-key.pem"
#define CLI_KEY  "certs/client-key.pem"
#define CLI_RPK  "certs/rpk/client-cert-rpk.der"
#define SVR_RPK  "certs/rpk/server-cert-rpk.der"

enum case_kind {
    /* Peer selects X.509 in server_certificate_type; client offered only RPK. */
    CASE_SERVER_X509 = 1,
    /* Peer omits server_certificate_type; client offered only RPK. */
    CASE_SERVER_OMIT = 2,
    /* Peer selects X.509 in client_certificate_type; client offered only RPK. */
    CASE_CLIENT_X509 = 3,
    /* Client offered both types and the server honestly selects X.509. */
    CASE_HONEST_X509 = 4,
    /* Both sides honestly negotiate a raw public key for the server. */
    CASE_HONEST_RPK = 5,
    /* Both sides honestly negotiate a raw public key for the client. */
    CASE_HONEST_CLIENT_RPK = 6
};

struct io_ctx {
    byte c2s[IO_CAP];
    int c2s_len;
    int c2s_off;
    byte s2c[IO_CAP];
    int s2c_len;
    int s2c_off;
};

static int io_write(WOLFSSL* ssl, char* data, int sz, void* ctx)
{
    struct io_ctx* io = (struct io_ctx*)ctx;
    byte* buf;
    int* len;
    int* off;

    if (wolfSSL_GetSide(ssl) == WOLFSSL_SERVER_END) {
        buf = io->s2c;
        len = &io->s2c_len;
        off = &io->s2c_off;
    }
    else {
        buf = io->c2s;
        len = &io->c2s_len;
        off = &io->c2s_off;
    }
    if (*off > 0 && *off <= *len) {
        memmove(buf, buf + *off, (size_t)(*len - *off));
        *len -= *off;
        *off = 0;
    }
    if (sz < 0 || *len < 0 || (size_t)(*len + sz) > IO_CAP)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    memcpy(buf + *len, data, (size_t)sz);
    *len += sz;
    return sz;
}

static int io_read(WOLFSSL* ssl, char* data, int sz, void* ctx)
{
    struct io_ctx* io = (struct io_ctx*)ctx;
    byte* buf;
    int* len;
    int* off;
    int avail;

    if (wolfSSL_GetSide(ssl) == WOLFSSL_SERVER_END) {
        buf = io->c2s;
        len = &io->c2s_len;
        off = &io->c2s_off;
    }
    else {
        buf = io->s2c;
        len = &io->s2c_len;
        off = &io->s2c_off;
    }
    avail = *len - *off;
    if (avail <= 0)
        return WOLFSSL_CBIO_ERR_WANT_READ;
    if (sz > avail)
        sz = avail;
    memcpy(data, buf + *off, (size_t)sz);
    *off += sz;
    return sz;
}

static int read_file(const char* path, byte** out, word32* out_sz)
{
    FILE* f;
    long sz;
    byte* buf;

    f = fopen(path, "rb");
    if (f == NULL)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    sz = ftell(f);
    if (sz <= 0 || sz > 1024 * 1024) {
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    buf = (byte*)malloc((size_t)sz);
    if (buf == NULL) {
        fclose(f);
        return -1;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);
    *out = buf;
    *out_sz = (word32)sz;
    return 0;
}

static int pin_file(WOLFSSL* ssl, const char* path)
{
    byte* buf = NULL;
    word32 sz = 0;
    int ret;

    if (read_file(path, &buf, &sz) != 0)
        return -1;
    ret = wolfSSL_set_expected_rpk(ssl, buf, sz);
    free(buf);
    return (ret == WOLFSSL_SUCCESS) ? 0 : -1;
}

/* True when buf contains a certificate-type extension (type, then a
 * 2-byte length, then the payload). */
static int has_pattern(const byte* buf, int len, const byte* pat, int pat_len)
{
    int i;

    if (buf == NULL || pat_len <= 0 || len < pat_len)
        return 0;
    for (i = 0; i <= len - pat_len; i++) {
        if (memcmp(buf + i, pat, (size_t)pat_len) == 0)
            return 1;
    }
    return 0;
}

static int err_is_retry(int err)
{
    return err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE;
}

/* Drive both ends. Returns 0 when both handshakes finish, -1 otherwise.
 * client_err is the first non-retry error from the client, else 0. */
static int pump(WOLFSSL* cli, WOLFSSL* srv, int rounds, int* client_err)
{
    int client_done = 0;
    int server_done = 0;
    int i;

    *client_err = 0;
    for (i = 0; i < rounds && (!client_done || !server_done); i++) {
        if (!client_done) {
            int ret = wolfSSL_connect(cli);
            if (ret == WOLFSSL_SUCCESS) {
                client_done = 1;
            }
            else {
                int err = wolfSSL_get_error(cli, ret);
                if (!err_is_retry(err)) {
                    *client_err = err;
                    return -1;
                }
            }
        }
        if (!server_done) {
            int ret = wolfSSL_accept(srv);
            if (ret == WOLFSSL_SUCCESS) {
                server_done = 1;
            }
            else {
                int err = wolfSSL_get_error(srv, ret);
                if (!err_is_retry(err))
                    return -1;
            }
        }
    }
    return (client_done && server_done) ? 0 : -1;
}

static int exchange_byte(WOLFSSL* cli, WOLFSSL* srv)
{
    char out = 'A';
    char in = 0;
    int ret;
    int err;
    int i;

    for (i = 0; i < 10; i++) {
        ret = wolfSSL_write(cli, &out, 1);
        if (ret == 1)
            break;
        err = wolfSSL_get_error(cli, ret);
        if (!err_is_retry(err))
            return -1;
        ret = wolfSSL_read(srv, &in, 1);
        err = wolfSSL_get_error(srv, ret);
        if (ret != 1 && !err_is_retry(err) && ret != 0)
            return -1;
    }
    if (ret != 1)
        return -1;
    for (i = 0; i < 10; i++) {
        ret = wolfSSL_read(srv, &in, 1);
        if (ret == 1)
            break;
        err = wolfSSL_get_error(srv, ret);
        if (!err_is_retry(err))
            return -1;
        ret = wolfSSL_write(cli, &out, 1);
        err = wolfSSL_get_error(cli, ret);
        if (ret != 1 && !err_is_retry(err))
            return -1;
    }
    return (ret == 1 && in == 'A') ? 0 : -1;
}

static void clear_extension_response(WOLFSSL* ssl, TLSX_Type type)
{
    TLSX* ext;

    for (ext = ssl->extensions; ext != NULL; ext = ext->next) {
        if (ext->type == type)
            ext->resp = 0;
    }
}

struct endpoints {
    WOLFSSL_CTX* cli_ctx;
    WOLFSSL_CTX* srv_ctx;
    WOLFSSL* cli;
    WOLFSSL* srv;
    struct io_ctx io;
};

static void endpoints_free(struct endpoints* ep)
{
    if (ep->cli != NULL)
        wolfSSL_free(ep->cli);
    if (ep->srv != NULL)
        wolfSSL_free(ep->srv);
    if (ep->cli_ctx != NULL)
        wolfSSL_CTX_free(ep->cli_ctx);
    if (ep->srv_ctx != NULL)
        wolfSSL_CTX_free(ep->srv_ctx);
    memset(ep, 0, sizeof(*ep));
}

/* Returns 0 on success. The peer is a normal wolfSSL server up to the point
 * it has parsed the ClientHello; the caller then rewrites the selection. */
static int setup_endpoints(struct endpoints* ep, int tls13, int kind)
{
    WOLFSSL_METHOD* (*cli_method)(void);
    WOLFSSL_METHOD* (*srv_method)(void);
    char only_rpk[1];
    char both[2];
    const char* srv_cert;
    int srv_cert_fmt;
    const char* cli_cert;
    int cli_cert_fmt;
    int server_type_cnt;
    int client_offers_only_rpk_server;
    int client_auth;

    memset(ep, 0, sizeof(*ep));
    only_rpk[0] = (char)WOLFSSL_CERT_TYPE_RPK;
    both[0] = (char)WOLFSSL_CERT_TYPE_RPK;
    both[1] = (char)WOLFSSL_CERT_TYPE_X509;

    if (tls13) {
#ifdef WOLFSSL_TLS13
        cli_method = wolfTLSv1_3_client_method;
        srv_method = wolfTLSv1_3_server_method;
#else
        (void)cli_method;
        (void)srv_method;
        return -1;
#endif
    }
    else {
#ifndef WOLFSSL_NO_TLS12
        cli_method = wolfTLSv1_2_client_method;
        srv_method = wolfTLSv1_2_server_method;
#else
        return -1;
#endif
    }

    client_offers_only_rpk_server =
        (kind == CASE_SERVER_X509 || kind == CASE_SERVER_OMIT);
    client_auth = (kind == CASE_CLIENT_X509 || kind == CASE_HONEST_CLIENT_RPK);
    if (kind == CASE_HONEST_RPK) {
        srv_cert = SVR_RPK;
        srv_cert_fmt = WOLFSSL_FILETYPE_ASN1;
    }
    else {
        srv_cert = SVR_CERT;
        srv_cert_fmt = WOLFSSL_FILETYPE_PEM;
    }
    if (client_auth) {
        cli_cert = CLI_RPK;
        cli_cert_fmt = WOLFSSL_FILETYPE_ASN1;
    }
    else {
        cli_cert = NULL;
        cli_cert_fmt = 0;
    }

    ep->cli_ctx = wolfSSL_CTX_new(cli_method());
    ep->srv_ctx = wolfSSL_CTX_new(srv_method());
    if (ep->cli_ctx == NULL || ep->srv_ctx == NULL)
        return -1;

    wolfSSL_CTX_clear_group_messages(ep->srv_ctx);
    wolfSSL_SetIORecv(ep->cli_ctx, io_read);
    wolfSSL_SetIOSend(ep->cli_ctx, io_write);
    wolfSSL_SetIORecv(ep->srv_ctx, io_read);
    wolfSSL_SetIOSend(ep->srv_ctx, io_write);

    if (wolfSSL_CTX_use_certificate_file(ep->srv_ctx, srv_cert, srv_cert_fmt)
            != WOLFSSL_SUCCESS)
        return -1;
    if (wolfSSL_CTX_use_PrivateKey_file(ep->srv_ctx, SVR_KEY,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        return -1;

    /* The downgrade only lands when ordinary path validation can succeed,
     * so the X.509 cases trust the CA that issued the server certificate.
     * The raw-key-only control does not: success there means the pin alone
     * authenticated the peer. */
    if (kind != CASE_HONEST_RPK) {
        if (wolfSSL_CTX_load_verify_locations(ep->cli_ctx, CA_FILE, NULL)
                != WOLFSSL_SUCCESS)
            return -1;
    }
    wolfSSL_CTX_set_verify(ep->cli_ctx, WOLFSSL_VERIFY_PEER, NULL);

    if (client_auth) {
        if (wolfSSL_CTX_use_certificate_file(ep->cli_ctx, cli_cert,
                cli_cert_fmt) != WOLFSSL_SUCCESS)
            return -1;
        if (wolfSSL_CTX_use_PrivateKey_file(ep->cli_ctx, CLI_KEY,
                WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
            return -1;
        wolfSSL_CTX_set_verify(ep->srv_ctx, WOLFSSL_VERIFY_PEER, NULL);
    }
    else {
        wolfSSL_CTX_set_verify(ep->srv_ctx, WOLFSSL_VERIFY_NONE, NULL);
    }

    ep->cli = wolfSSL_new(ep->cli_ctx);
    ep->srv = wolfSSL_new(ep->srv_ctx);
    if (ep->cli == NULL || ep->srv == NULL)
        return -1;
    wolfSSL_SetIOReadCtx(ep->cli, &ep->io);
    wolfSSL_SetIOWriteCtx(ep->cli, &ep->io);
    wolfSSL_SetIOReadCtx(ep->srv, &ep->io);
    wolfSSL_SetIOWriteCtx(ep->srv, &ep->io);
    wolfSSL_clear_group_messages(ep->srv);

    if (client_offers_only_rpk_server || kind == CASE_HONEST_RPK) {
        if (wolfSSL_set_server_cert_type(ep->cli, only_rpk, 1)
                != WOLFSSL_SUCCESS)
            return -1;
        if (wolfSSL_set_server_cert_type(ep->srv, only_rpk, 1)
                != WOLFSSL_SUCCESS)
            return -1;
    }
    else if (kind == CASE_HONEST_X509) {
        if (wolfSSL_set_server_cert_type(ep->cli, both, 2) != WOLFSSL_SUCCESS)
            return -1;
        /* Server preference lists X.509 first, so an honest peer picks it. */
        both[0] = (char)WOLFSSL_CERT_TYPE_X509;
        both[1] = (char)WOLFSSL_CERT_TYPE_RPK;
        if (wolfSSL_set_server_cert_type(ep->srv, both, 2) != WOLFSSL_SUCCESS)
            return -1;
        both[0] = (char)WOLFSSL_CERT_TYPE_RPK;
        both[1] = (char)WOLFSSL_CERT_TYPE_X509;
    }

    if (kind == CASE_CLIENT_X509 || kind == CASE_HONEST_CLIENT_RPK) {
        if (wolfSSL_set_client_cert_type(ep->cli, only_rpk, 1)
                != WOLFSSL_SUCCESS)
            return -1;
        if (wolfSSL_set_client_cert_type(ep->srv, only_rpk, 1)
                != WOLFSSL_SUCCESS)
            return -1;
    }

    /* Pin a raw key that is not the X.509 server key. Path validation of
     * that certificate must not satisfy this pin. */
    if (client_offers_only_rpk_server) {
        if (pin_file(ep->cli, CLI_RPK) != 0)
            return -1;
    }
    if (kind == CASE_HONEST_RPK) {
        if (pin_file(ep->cli, SVR_RPK) != 0)
            return -1;
    }
    if (client_auth) {
        if (pin_file(ep->srv, CLI_RPK) != 0)
            return -1;
    }

    server_type_cnt = ep->srv->options.rpkConfig.preferred_ServerCertTypeCnt;
    (void)server_type_cnt;
    return 0;
}

static const char* err_string(int err)
{
    static char buf[WOLFSSL_MAX_ERROR_SZ];

    wolfSSL_ERR_error_string((unsigned long)err, buf);
    return buf;
}

/* 0: behavior matches the fixed library.
 * 1: unoffered type was accepted (vulnerability present).
 * 2: harness could not exercise the path. */
static int run_case(const char* name, int tls13, int kind)
{
    struct endpoints ep;
    int ret;
    int client_err = 0;
    int negotiated = -99;
    int attack;
    const byte client_offer_rpk[] = {
        0x00, 0x14, 0x00, 0x02, 0x01, WOLFSSL_CERT_TYPE_RPK
    };
    const byte server_sel_x509[] = {
        0x00, 0x14, 0x00, 0x01, WOLFSSL_CERT_TYPE_X509
    };
    const byte client_ctype_offer[] = {
        0x00, 0x13, 0x00, 0x02, 0x01, WOLFSSL_CERT_TYPE_RPK
    };
    const byte client_ctype_x509[] = {
        0x00, 0x13, 0x00, 0x01, WOLFSSL_CERT_TYPE_X509
    };

    attack = (kind == CASE_SERVER_X509 || kind == CASE_SERVER_OMIT ||
              kind == CASE_CLIENT_X509);

    printf("== %s ==\n", name);
    if (setup_endpoints(&ep, tls13, kind) != 0) {
        printf("  SETUP failed before the handshake\n");
        endpoints_free(&ep);
        return 2;
    }

    ret = wolfSSL_connect(ep.cli);
    if (ret == WOLFSSL_SUCCESS ||
            !err_is_retry(wolfSSL_get_error(ep.cli, ret))) {
        printf("  SETUP client hello did not pause (%d)\n",
            wolfSSL_get_error(ep.cli, ret));
        endpoints_free(&ep);
        return 2;
    }

    if (kind == CASE_SERVER_X509 || kind == CASE_SERVER_OMIT ||
            kind == CASE_HONEST_RPK) {
        if (!has_pattern(ep.io.c2s, ep.io.c2s_len, client_offer_rpk,
                (int)sizeof(client_offer_rpk))) {
            printf("  SETUP client hello did not offer only the raw key\n");
            endpoints_free(&ep);
            return 2;
        }
    }
    if (kind == CASE_CLIENT_X509 || kind == CASE_HONEST_CLIENT_RPK) {
        if (!has_pattern(ep.io.c2s, ep.io.c2s_len, client_ctype_offer,
                (int)sizeof(client_ctype_offer))) {
            printf("  SETUP client hello did not offer only a raw client key\n");
            endpoints_free(&ep);
            return 2;
        }
    }

    /* Honest cases never rewrite the peer. Attack cases pause the server
     * after it has chosen a type from the ClientHello and before it writes
     * ServerHello / EncryptedExtensions, then put a type on the wire that
     * the client did not offer. */
    if (attack) {
        ep.srv->options.returnOnGoodCh = 1;
        ep.srv->error = 0;
        ret = wolfSSL_accept(ep.srv);
        if (ep.io.s2c_len != 0) {
            printf("  SETUP server wrote before the certificate type could "
                   "be replaced\n");
            endpoints_free(&ep);
            return 2;
        }
        if (ret == WOLFSSL_SUCCESS ||
                wolfSSL_get_error(ep.srv, ret) != WOLFSSL_ERROR_WANT_WRITE) {
            printf("  SETUP server did not pause after ClientHello (%d %s)\n",
                wolfSSL_get_error(ep.srv, ret),
                err_string(wolfSSL_get_error(ep.srv, ret)));
            endpoints_free(&ep);
            return 2;
        }

        if (kind == CASE_SERVER_X509 || kind == CASE_SERVER_OMIT) {
            if (ep.srv->options.rpkState.sending_ServerCertTypeCnt != 1 ||
                    ep.srv->options.rpkState.sending_ServerCertTypes[0] !=
                        WOLFSSL_CERT_TYPE_RPK) {
                printf("  SETUP server did not select the offered raw key\n");
                endpoints_free(&ep);
                return 2;
            }
        }
        if (kind == CASE_CLIENT_X509) {
            if (ep.srv->options.rpkState.sending_ClientCertTypeCnt != 1 ||
                    ep.srv->options.rpkState.sending_ClientCertTypes[0] !=
                        WOLFSSL_CERT_TYPE_RPK) {
                printf("  SETUP server did not select the offered raw "
                       "client key\n");
                endpoints_free(&ep);
                return 2;
            }
        }

        if (kind == CASE_SERVER_X509) {
            ep.srv->options.rpkState.sending_ServerCertTypes[0] =
                WOLFSSL_CERT_TYPE_X509;
        }
        else if (kind == CASE_SERVER_OMIT) {
            /* Drop the extension, but still send a normal X.509 chain.
             * TLS 1.2 frames a raw key differently; leaving the selected
             * type as RPK would make the Certificate message unparsable
             * and would not exercise the default-to-X.509 path. */
            ep.srv->options.rpkState.sending_ServerCertTypes[0] =
                WOLFSSL_CERT_TYPE_X509;
            clear_extension_response(ep.srv, TLSX_SERVER_CERTIFICATE_TYPE);
        }
        else if (kind == CASE_CLIENT_X509) {
            ep.srv->options.rpkState.sending_ClientCertTypes[0] =
                WOLFSSL_CERT_TYPE_X509;
        }

        ep.srv->options.returnOnGoodCh = 0;
        ep.srv->error = 0;
        ret = wolfSSL_accept(ep.srv);
        if (ret == WOLFSSL_SUCCESS ||
                !err_is_retry(wolfSSL_get_error(ep.srv, ret))) {
            printf("  SETUP server flight failed (%d %s)\n",
                wolfSSL_get_error(ep.srv, ret),
                err_string(wolfSSL_get_error(ep.srv, ret)));
            endpoints_free(&ep);
            return 2;
        }

        if (!tls13 && kind == CASE_SERVER_X509 &&
                !has_pattern(ep.io.s2c, ep.io.s2c_len, server_sel_x509,
                    (int)sizeof(server_sel_x509))) {
            printf("  SETUP server hello did not carry X.509 as the "
                   "selected server certificate type\n");
            endpoints_free(&ep);
            return 2;
        }
        if (!tls13 && kind == CASE_SERVER_OMIT &&
                has_pattern(ep.io.s2c, ep.io.s2c_len, server_sel_x509, 4)) {
            printf("  SETUP server hello still carried server_certificate_type\n");
            endpoints_free(&ep);
            return 2;
        }
        if (!tls13 && kind == CASE_CLIENT_X509 &&
                !has_pattern(ep.io.s2c, ep.io.s2c_len, client_ctype_x509,
                    (int)sizeof(client_ctype_x509))) {
            printf("  SETUP server hello did not carry X.509 as the "
                   "selected client certificate type\n");
            endpoints_free(&ep);
            return 2;
        }

        /* The client certificate is authenticated against the type the
         * server actually selected. Put that back after the flight that
         * advertised the unoffered type has already been written, so a
         * later rejection is the client's and not the server's. */
        if (kind == CASE_CLIENT_X509) {
            ep.srv->options.rpkState.sending_ClientCertTypes[0] =
                WOLFSSL_CERT_TYPE_RPK;
        }
        ep.srv->error = 0;
    }

    ret = pump(ep.cli, ep.srv, 40, &client_err);
    if (!attack) {
        if (ret != 0) {
            printf("  FAIL honest handshake did not complete (client %d %s)\n",
                client_err, err_string(client_err));
            endpoints_free(&ep);
            return 2;
        }
        if (exchange_byte(ep.cli, ep.srv) != 0) {
            printf("  FAIL application data did not flow\n");
            endpoints_free(&ep);
            return 2;
        }
        printf("  ok\n");
        endpoints_free(&ep);
        return 0;
    }

    if (ret == 0) {
        int neg_client = -99;

        (void)wolfSSL_get_negotiated_server_cert_type(ep.cli, &negotiated);
        (void)wolfSSL_get_negotiated_client_cert_type(ep.cli, &neg_client);
        if (kind == CASE_SERVER_X509 && negotiated != WOLFSSL_CERT_TYPE_X509) {
            printf("  SETUP completed without adopting X.509 as the server "
                   "certificate type (%d)\n", negotiated);
            endpoints_free(&ep);
            return 2;
        }
        if (kind == CASE_SERVER_OMIT &&
                negotiated != WOLFSSL_CERT_TYPE_UNKNOWN) {
            printf("  SETUP omit still negotiated a server certificate type "
                   "(%d)\n", negotiated);
            endpoints_free(&ep);
            return 2;
        }
        if (kind == CASE_CLIENT_X509 &&
                neg_client != WOLFSSL_CERT_TYPE_X509) {
            printf("  SETUP completed without adopting X.509 as the client "
                   "certificate type (%d)\n", neg_client);
            endpoints_free(&ep);
            return 2;
        }
        if (exchange_byte(ep.cli, ep.srv) != 0) {
            printf("  handshake returned success but application data "
                   "failed\n");
            endpoints_free(&ep);
            return 2;
        }
        printf("  VULNERABLE handshake completed (server cert type %d, "
               "client cert type %d)\n", negotiated, neg_client);
        endpoints_free(&ep);
        return 1;
    }

    if (client_err != UNSUPPORTED_CERTIFICATE) {
        printf("  FAIL client error %d (%s), want unsupported certificate\n",
            client_err, err_string(client_err));
        endpoints_free(&ep);
        return 2;
    }
    printf("  rejected\n");
    endpoints_free(&ep);
    return 0;
}

int main(void)
{
    int failed = 0;
    int rc;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed\n");
        return 2;
    }

#ifndef HAVE_RPK
    fprintf(stderr, "HAVE_RPK is not enabled; configure with --enable-rpk\n");
    wolfSSL_Cleanup();
    return 2;
#else
    rc = run_case("TLS1.2 server cert type X.509 not offered", 0,
        CASE_SERVER_X509);
    if (rc != 0)
        failed = 1;
    rc = run_case("TLS1.2 server cert type omitted", 0, CASE_SERVER_OMIT);
    if (rc != 0)
        failed = 1;
    rc = run_case("TLS1.2 client cert type X.509 not offered", 0,
        CASE_CLIENT_X509);
    if (rc != 0)
        failed = 1;
    rc = run_case("TLS1.2 honest X.509 when offered", 0, CASE_HONEST_X509);
    if (rc != 0)
        failed = 1;
    rc = run_case("TLS1.2 honest raw public key", 0, CASE_HONEST_RPK);
    if (rc != 0)
        failed = 1;
    rc = run_case("TLS1.2 honest client raw public key", 0,
        CASE_HONEST_CLIENT_RPK);
    if (rc != 0)
        failed = 1;

#ifdef WOLFSSL_TLS13
    rc = run_case("TLS1.3 server cert type X.509 not offered", 1,
        CASE_SERVER_X509);
    if (rc != 0)
        failed = 1;
    rc = run_case("TLS1.3 server cert type omitted", 1, CASE_SERVER_OMIT);
    if (rc != 0)
        failed = 1;
    rc = run_case("TLS1.3 client cert type X.509 not offered", 1,
        CASE_CLIENT_X509);
    if (rc != 0)
        failed = 1;
    rc = run_case("TLS1.3 honest X.509 when offered", 1, CASE_HONEST_X509);
    if (rc != 0)
        failed = 1;
    rc = run_case("TLS1.3 honest raw public key", 1, CASE_HONEST_RPK);
    if (rc != 0)
        failed = 1;
    rc = run_case("TLS1.3 honest client raw public key", 1,
        CASE_HONEST_CLIENT_RPK);
    if (rc != 0)
        failed = 1;
#else
    printf("TLS 1.3 not built; those cases were not run\n");
    failed = 1;
#endif

    wolfSSL_Cleanup();
    if (failed) {
        printf("RESULT fail\n");
        return 1;
    }
    printf("RESULT pass\n");
    return 0;
#endif
}

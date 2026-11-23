/* Handshake tests for the OpenSSL-compat hostname check.
 *
 * These tests are expected to FAIL while a peer certificate with no subject
 * common name and no subject alternative name is accepted after
 * wolfSSL_set1_host() / X509_VERIFY_PARAM_set1_host(). They pass once that
 * certificate is rejected with DOMAIN_NAME_MISMATCH.
 *
 * Build and run (from the repository root, after the library is configured
 * with OpenSSL compatibility, certificate generation, and key generation):
 *
 *   ./autogen.sh
 *   ./configure --enable-opensslextra --enable-opensslall \
 *       --enable-certgen --enable-certext --enable-keygen --disable-examples
 *   make -j src/libwolfssl.la
 *   gcc -std=c99 -Wall -Wextra -o tests/api/test_nameless_host_verify \
 *       tests/api/test_nameless_host_verify.c \
 *       -I. src/.libs/libwolfssl.a -lm -pthread
 *   ./tests/api/test_nameless_host_verify
 *
 * No private key material is embedded. Keys are generated at runtime and
 * stay in process memory.
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/error-ssl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define DER_CAP 8192
#define KEY_CAP 4096
#define IO_CAP  (64 * 1024)
#define HOST_OK "www.example.com"
#define HOST_BAD "evil.test"

#if !defined(OPENSSL_EXTRA) || !defined(WOLFSSL_CERT_GEN) || \
    !defined(WOLFSSL_CERT_EXT) || !defined(WOLFSSL_KEY_GEN) || \
    defined(NO_RSA) || defined(NO_SHA256)
#error "Configure with --enable-opensslextra --enable-certgen --enable-certext --enable-keygen"
#endif

#if defined(WOLFSSL_CUSTOM_OID) && defined(HAVE_OID_ENCODING) && \
    defined(WOLFSSL_ALT_NAMES) && !defined(IGNORE_NAME_CONSTRAINTS)
#define HAVE_NC_TESTS 1
#endif

typedef struct {
    byte der[DER_CAP];
    int  sz;
} cert_buf;

typedef struct {
    byte der[KEY_CAP];
    int  sz;
} key_buf;

typedef struct {
    byte c2s[IO_CAP];
    int  c2s_len;
    int  c2s_rd;
    byte s2c[IO_CAP];
    int  s2c_len;
    int  s2c_rd;
} mem_io;

static int g_failures = 0;

static void fail_msg(const char* name, const char* msg)
{
    fprintf(stderr, "FAIL %s: %s\n", name, msg);
    g_failures++;
}

static const char* err_str(int err, char* buf)
{
    return wolfSSL_ERR_error_string((unsigned long)err, buf);
}

static int io_append(byte* dst, int* len, int cap, const char* src, int sz)
{
    if (sz < 0 || *len > cap - sz)
        return WOLFSSL_CBIO_ERR_GENERAL;
    memcpy(dst + *len, src, (size_t)sz);
    *len += sz;
    return sz;
}

static int io_take(byte* src, int len, int* rd, char* dst, int sz)
{
    int avail = len - *rd;

    if (avail <= 0)
        return WOLFSSL_CBIO_ERR_WANT_READ;
    if (sz > avail)
        sz = avail;
    memcpy(dst, src + *rd, (size_t)sz);
    *rd += sz;
    return sz;
}

static int client_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    mem_io* io = (mem_io*)ctx;
    (void)ssl;
    return io_append(io->c2s, &io->c2s_len, IO_CAP, buf, sz);
}

static int client_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    mem_io* io = (mem_io*)ctx;
    (void)ssl;
    return io_take(io->s2c, io->s2c_len, &io->s2c_rd, buf, sz);
}

static int server_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    mem_io* io = (mem_io*)ctx;
    (void)ssl;
    return io_append(io->s2c, &io->s2c_len, IO_CAP, buf, sz);
}

static int server_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    mem_io* io = (mem_io*)ctx;
    (void)ssl;
    return io_take(io->c2s, io->c2s_len, &io->c2s_rd, buf, sz);
}

static int make_rsa(WC_RNG* rng, RsaKey* key, key_buf* out)
{
    int ret;

    ret = wc_InitRsaKey(key, NULL);
    if (ret != 0)
        return ret;
    ret = wc_MakeRsaKey(key, 2048, 65537, rng);
    if (ret != 0)
        return ret;
    ret = wc_RsaKeyToDer(key, out->der, KEY_CAP);
    if (ret <= 0)
        return ret == 0 ? -1 : ret;
    out->sz = ret;
    return 0;
}

static int sign_cert(Cert* cert, byte* der, RsaKey* subject, RsaKey* signer,
    WC_RNG* rng)
{
    int body;

    body = wc_MakeCert(cert, der, DER_CAP, subject, NULL, rng);
    if (body < 0)
        return body;
    return wc_SignCert(cert->bodySz, cert->sigType, der, DER_CAP,
        signer, NULL, rng);
}

static void set_org(CertName* name, const char* org, const char* cn)
{
    strncpy(name->country, "US", CTC_NAME_SIZE - 1);
    strncpy(name->org, org, CTC_NAME_SIZE - 1);
    if (cn != NULL)
        strncpy(name->commonName, cn, CTC_NAME_SIZE - 1);
}

/* GeneralNames holding one dNSName. Placed in the SAN extension value. */
static int put_dns_san(Cert* cert, const char* dns)
{
    size_t n = strlen(dns);
    byte* p;

    if (n == 0 || n > 120)
        return -1;
    if ((int)(2 + 2 + n) > (int)sizeof(cert->altNames))
        return -1;
    p = cert->altNames;
    p[0] = 0x30;
    p[1] = (byte)(2 + n);
    p[2] = 0x82;
    p[3] = (byte)n;
    memcpy(p + 4, dns, n);
    cert->altNamesSz = (int)(4 + n);
    return 0;
}

static int build_ca(WC_RNG* rng, RsaKey* key, cert_buf* out, const char* cn)
{
    Cert cert;
    int sz;

    if (wc_InitCert(&cert) != 0)
        return -1;
    cert.isCA = 1;
    cert.basicConstCrit = 1;
    cert.keyUsage = KEYUSE_KEY_CERT_SIGN | KEYUSE_CRL_SIGN;
    cert.sigType = CTC_SHA256wRSA;
    set_org(&cert.subject, "Nameless Host Test", cn);
    if (wc_SetSubjectKeyIdFromPublicKey(&cert, key, NULL) != 0)
        return -1;
    sz = sign_cert(&cert, out->der, key, key, rng);
    if (sz <= 0)
        return sz == 0 ? -1 : sz;
    out->sz = sz;
    return 0;
}

#ifdef HAVE_NC_TESTS
/* NameConstraints permittedSubtrees, IMPLICIT [0] GeneralSubtrees, one
 * dNSName "example.com". PKIX1Implicit88 replaces the GeneralSubtrees
 * SEQUENCE tag with the context tag, so there is no extra SEQUENCE under A0.
 * 30 11
 *   A0 0F
 *     30 0D
 *       82 0B example.com
 */
static const byte kDnsPermittedExampleCom[] = {
    0x30, 0x11,
      0xA0, 0x0F,
        0x30, 0x0D,
          0x82, 0x0B,
          'e','x','a','m','p','l','e','.','c','o','m'
};

static int build_constrained_ca(WC_RNG* rng, RsaKey* subject, RsaKey* issuer,
    const byte* issuerDer, int issuerSz, cert_buf* out)
{
    Cert cert;
    int sz;

    if (wc_InitCert(&cert) != 0)
        return -1;
    cert.isCA = 1;
    cert.basicConstCrit = 1;
    cert.keyUsage = KEYUSE_KEY_CERT_SIGN | KEYUSE_CRL_SIGN;
    cert.sigType = CTC_SHA256wRSA;
    set_org(&cert.subject, "Constrained Issuer", "Constrained CA");
    if ((sz = wc_SetIssuerBuffer(&cert, issuerDer, issuerSz)) != 0)
        return sz;
    if ((sz = wc_SetAuthKeyIdFromPublicKey(&cert, issuer, NULL)) != 0)
        return sz;
    if ((sz = wc_SetSubjectKeyIdFromPublicKey(&cert, subject, NULL)) != 0)
        return sz;
    if ((sz = wc_SetCustomExtension(&cert, 1, "2.5.29.30",
            kDnsPermittedExampleCom,
            (word32)sizeof(kDnsPermittedExampleCom))) != 0)
        return sz;
    sz = sign_cert(&cert, out->der, subject, issuer, rng);
    if (sz <= 0)
        return sz == 0 ? -1 : sz;
    out->sz = sz;
    return 0;
}
#endif /* HAVE_NC_TESTS */

static int build_leaf(WC_RNG* rng, RsaKey* subject, RsaKey* issuer,
    const byte* issuerDer, int issuerSz, const char* cn, const char* san,
    cert_buf* out)
{
    Cert cert;
    int sz;

    if (wc_InitCert(&cert) != 0)
        return -1;
    cert.isCA = 0;
    cert.keyUsage = KEYUSE_DIGITAL_SIG;
    cert.sigType = CTC_SHA256wRSA;
    set_org(&cert.subject, "Nameless Leaf", cn);
    if ((sz = wc_SetIssuerBuffer(&cert, issuerDer, issuerSz)) != 0)
        return sz;
    if ((sz = wc_SetAuthKeyIdFromPublicKey(&cert, issuer, NULL)) != 0)
        return sz;
    if ((sz = wc_SetSubjectKeyIdFromPublicKey(&cert, subject, NULL)) != 0)
        return sz;
    if (san != NULL && (sz = put_dns_san(&cert, san)) != 0)
        return sz;
    sz = sign_cert(&cert, out->der, subject, issuer, rng);
    if (sz <= 0)
        return sz == 0 ? -1 : sz;
    out->sz = sz;
    return 0;
}

static int describe_cert(const char* label, const byte* der, int sz,
    int* hasCn, int* hasAlt, int* hasPermitted)
{
    DecodedCert decoded;
    int ret;
    char subject[WC_ASN_NAME_MAX];

    *hasCn = -1;
    *hasAlt = -1;
    *hasPermitted = -1;
    wc_InitDecodedCert(&decoded, der, (word32)sz, NULL);
    ret = wc_ParseCert(&decoded, CERT_TYPE, NO_VERIFY, NULL);
    if (ret != 0) {
        fprintf(stderr, "parse %s failed: %d\n", label, ret);
        wc_FreeDecodedCert(&decoded);
        return ret;
    }
    *hasCn = decoded.subjectCN != NULL;
    *hasAlt = decoded.altNames != NULL;
#ifndef IGNORE_NAME_CONSTRAINTS
    *hasPermitted = decoded.permittedNames != NULL;
#endif
    memcpy(subject, decoded.subject, sizeof(subject));
    subject[sizeof(subject) - 1] = '\0';
    fprintf(stderr, "cert %s subject=\"%s\" cn=%d alt=%d permittedDns=%d\n",
        label, subject, *hasCn, *hasAlt, *hasPermitted);
    wc_FreeDecodedCert(&decoded);
    return 0;
}

typedef struct {
    const byte* ca;
    int         caSz;
    const byte* chain;      /* intermediate sent after the leaf, or NULL */
    int         chainSz;
    const byte* serverCert;
    int         serverCertSz;
    const byte* serverKey;
    int         serverKeySz;
    const byte* clientCert; /* optional client certificate */
    int         clientCertSz;
    const byte* clientKey;
    int         clientKeySz;
    int         clientVerifyPeer;
    int         serverVerifyPeer;
    const char* clientHost;          /* wolfSSL_set1_host */
    int         clientHostViaParam;  /* set the same name through get0_param */
    const char* clientDomain;        /* wolfSSL_check_domain_name */
    const char* serverHost;          /* server wolfSSL_set1_host */
    WOLFSSL_METHOD* (*clientMethod)(void);
    WOLFSSL_METHOD* (*serverMethod)(void);
} hs_spec;

static int run_handshake(const hs_spec* spec, int* clientErr, int* serverErr,
    int* wrote)
{
    WOLFSSL_CTX* cctx = NULL;
    WOLFSSL_CTX* sctx = NULL;
    WOLFSSL* client = NULL;
    WOLFSSL* server = NULL;
    mem_io io;
    int ret = -1;
    int rounds;
    int cDone = 0;
    int sDone = 0;
    WOLFSSL_X509* extra = NULL;

    memset(&io, 0, sizeof(io));
    *clientErr = 0;
    *serverErr = 0;
    *wrote = 0;

    cctx = wolfSSL_CTX_new(spec->clientMethod());
    sctx = wolfSSL_CTX_new(spec->serverMethod());
    if (cctx == NULL || sctx == NULL)
        goto done;

    wolfSSL_CTX_SetIORecv(cctx, client_recv);
    wolfSSL_CTX_SetIOSend(cctx, client_send);
    wolfSSL_CTX_SetIORecv(sctx, server_recv);
    wolfSSL_CTX_SetIOSend(sctx, server_send);

    if (spec->clientVerifyPeer)
        wolfSSL_CTX_set_verify(cctx, WOLFSSL_VERIFY_PEER, NULL);
    else
        wolfSSL_CTX_set_verify(cctx, WOLFSSL_VERIFY_NONE, NULL);

    if (wolfSSL_CTX_load_verify_buffer(cctx, spec->ca, spec->caSz,
            WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
        goto done;

    if (spec->clientCert != NULL) {
        if (wolfSSL_CTX_use_certificate_buffer(cctx, spec->clientCert,
                spec->clientCertSz, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
            goto done;
        if (wolfSSL_CTX_use_PrivateKey_buffer(cctx, spec->clientKey,
                spec->clientKeySz, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
            goto done;
    }

    if (wolfSSL_CTX_use_certificate_buffer(sctx, spec->serverCert,
            spec->serverCertSz, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
        goto done;
    if (wolfSSL_CTX_use_PrivateKey_buffer(sctx, spec->serverKey,
            spec->serverKeySz, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
        goto done;
    if (spec->chain != NULL) {
        const unsigned char* p = spec->chain;
        extra = wolfSSL_d2i_X509(NULL, &p, spec->chainSz);
        if (extra == NULL)
            goto done;
        if (wolfSSL_CTX_add_extra_chain_cert(sctx, extra) != 1)
            goto done;
        extra = NULL; /* owned by the context on success */
    }

    if (spec->serverVerifyPeer) {
        wolfSSL_CTX_set_verify(sctx,
            WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        if (wolfSSL_CTX_load_verify_buffer(sctx, spec->ca, spec->caSz,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
            goto done;
    }

    client = wolfSSL_new(cctx);
    server = wolfSSL_new(sctx);
    if (client == NULL || server == NULL)
        goto done;
    wolfSSL_SetIOReadCtx(client, &io);
    wolfSSL_SetIOWriteCtx(client, &io);
    wolfSSL_SetIOReadCtx(server, &io);
    wolfSSL_SetIOWriteCtx(server, &io);

    if (spec->clientHost != NULL) {
        if (spec->clientHostViaParam) {
            WOLFSSL_X509_VERIFY_PARAM* param = wolfSSL_get0_param(client);
            if (param == NULL ||
                wolfSSL_X509_VERIFY_PARAM_set1_host(param, spec->clientHost,
                    0) != WOLFSSL_SUCCESS)
                goto done;
        }
        else if (wolfSSL_set1_host(client, spec->clientHost) !=
                 WOLFSSL_SUCCESS) {
            goto done;
        }
    }
    if (spec->clientDomain != NULL) {
        if (wolfSSL_check_domain_name(client, spec->clientDomain) !=
            WOLFSSL_SUCCESS)
            goto done;
    }
    if (spec->serverHost != NULL) {
        if (wolfSSL_set1_host(server, spec->serverHost) != WOLFSSL_SUCCESS)
            goto done;
    }

    for (rounds = 0; rounds < 40 && (!cDone || !sDone); rounds++) {
        if (!cDone) {
            int rc = wolfSSL_connect(client);
            if (rc == WOLFSSL_SUCCESS) {
                cDone = 1;
            }
            else {
                int err = wolfSSL_get_error(client, rc);
                if (err != WOLFSSL_ERROR_WANT_READ &&
                    err != WOLFSSL_ERROR_WANT_WRITE) {
                    *clientErr = err;
                    cDone = 1;
                }
            }
        }
        if (!sDone) {
            int rc = wolfSSL_accept(server);
            if (rc == WOLFSSL_SUCCESS) {
                sDone = 1;
            }
            else {
                int err = wolfSSL_get_error(server, rc);
                if (err != WOLFSSL_ERROR_WANT_READ &&
                    err != WOLFSSL_ERROR_WANT_WRITE) {
                    *serverErr = err;
                    sDone = 1;
                }
            }
        }
        if (*clientErr != 0 && *serverErr != 0)
            break;
    }

    if (*clientErr == 0 && *serverErr == 0 && cDone && sDone) {
        const char msg[] = "application-data";
        int n = wolfSSL_write(client, msg, (int)sizeof(msg) - 1);
        *wrote = n;
        ret = WOLFSSL_SUCCESS;
    }
    else {
        ret = -1;
    }

done:
    wolfSSL_free(client);
    wolfSSL_free(server);
    wolfSSL_CTX_free(cctx);
    wolfSSL_CTX_free(sctx);
    if (extra != NULL)
        wolfSSL_X509_free(extra);
    return ret;
}

static void expect_client_mismatch(const char* name, const hs_spec* spec)
{
    int clientErr = 0;
    int serverErr = 0;
    int wrote = 0;
    int rc;
    char buf[WOLFSSL_MAX_ERROR_SZ];

    rc = run_handshake(spec, &clientErr, &serverErr, &wrote);
    if (rc == WOLFSSL_SUCCESS) {
        fprintf(stderr,
            "FAIL %s: handshake succeeded and the client wrote %d bytes\n",
            name, wrote);
        g_failures++;
        return;
    }
    if (clientErr != DOMAIN_NAME_MISMATCH) {
        fprintf(stderr,
            "FAIL %s: client error %d (%s), server error %d (%s); "
            "expected DOMAIN_NAME_MISMATCH (%d)\n",
            name, clientErr, err_str(clientErr, buf),
            serverErr, err_str(serverErr, buf), DOMAIN_NAME_MISMATCH);
        g_failures++;
        return;
    }
    if (wrote > 0) {
        fprintf(stderr, "FAIL %s: application data was written (%d)\n",
            name, wrote);
        g_failures++;
        return;
    }
    printf("PASS %s\n", name);
    fflush(stdout);
}

static void expect_server_mismatch(const char* name, const hs_spec* spec)
{
    int clientErr = 0;
    int serverErr = 0;
    int wrote = 0;
    int rc;
    char cbuf[WOLFSSL_MAX_ERROR_SZ];
    char sbuf[WOLFSSL_MAX_ERROR_SZ];

    rc = run_handshake(spec, &clientErr, &serverErr, &wrote);
    if (rc == WOLFSSL_SUCCESS) {
        fprintf(stderr,
            "FAIL %s: handshake succeeded and the client wrote %d bytes\n",
            name, wrote);
        g_failures++;
        return;
    }
    if (serverErr != DOMAIN_NAME_MISMATCH) {
        fprintf(stderr,
            "FAIL %s: server error %d (%s), client error %d (%s); "
            "expected DOMAIN_NAME_MISMATCH (%d)\n",
            name, serverErr, err_str(serverErr, sbuf),
            clientErr, err_str(clientErr, cbuf), DOMAIN_NAME_MISMATCH);
        g_failures++;
        return;
    }
    if (wrote > 0) {
        fprintf(stderr, "FAIL %s: application data was written (%d)\n",
            name, wrote);
        g_failures++;
        return;
    }
    printf("PASS %s\n", name);
    fflush(stdout);
}

static void expect_success(const char* name, const hs_spec* spec)
{
    int clientErr = 0;
    int serverErr = 0;
    int wrote = 0;
    int rc;
    char cbuf[WOLFSSL_MAX_ERROR_SZ];
    char sbuf[WOLFSSL_MAX_ERROR_SZ];

    rc = run_handshake(spec, &clientErr, &serverErr, &wrote);
    if (rc != WOLFSSL_SUCCESS || wrote != (int)strlen("application-data")) {
        fprintf(stderr,
            "FAIL %s: handshake rc=%d client=%d (%s) server=%d (%s) wrote=%d\n",
            name, rc, clientErr, err_str(clientErr, cbuf),
            serverErr, err_str(serverErr, sbuf), wrote);
        g_failures++;
        return;
    }
    printf("PASS %s\n", name);
    fflush(stdout);
}

static void expect_client_error(const char* name, const hs_spec* spec, int want)
{
    int clientErr = 0;
    int serverErr = 0;
    int wrote = 0;
    int rc;
    char buf[WOLFSSL_MAX_ERROR_SZ];

    rc = run_handshake(spec, &clientErr, &serverErr, &wrote);
    if (rc == WOLFSSL_SUCCESS || clientErr != want || wrote > 0) {
        fprintf(stderr,
            "FAIL %s: rc=%d client=%d (%s) server=%d wrote=%d, expected %d\n",
            name, rc, clientErr, err_str(clientErr, buf), serverErr, wrote,
            want);
        g_failures++;
        return;
    }
    printf("PASS %s\n", name);
    fflush(stdout);
}

static int x509_verify_host(const byte* ca, int caSz, const byte* leaf,
    int leafSz, const char* host, int* verifyRet, int* xerr)
{
    const unsigned char* p;
    WOLFSSL_X509* xca = NULL;
    WOLFSSL_X509* xleaf = NULL;
    WOLFSSL_X509_STORE* store = NULL;
    WOLFSSL_X509_STORE_CTX* ctx = NULL;
    WOLFSSL_X509_VERIFY_PARAM* param;
    int rc = -1;

    *verifyRet = -1;
    *xerr = 0;
    p = ca;
    xca = wolfSSL_d2i_X509(NULL, &p, caSz);
    p = leaf;
    xleaf = wolfSSL_d2i_X509(NULL, &p, leafSz);
    store = wolfSSL_X509_STORE_new();
    ctx = wolfSSL_X509_STORE_CTX_new();
    if (xca == NULL || xleaf == NULL || store == NULL || ctx == NULL)
        goto done;
    if (wolfSSL_X509_STORE_add_cert(store, xca) != WOLFSSL_SUCCESS)
        goto done;
    if (wolfSSL_X509_STORE_CTX_init(ctx, store, xleaf, NULL) != WOLFSSL_SUCCESS)
        goto done;
    param = wolfSSL_X509_STORE_CTX_get0_param(ctx);
    if (param == NULL ||
        wolfSSL_X509_VERIFY_PARAM_set1_host(param, host, 0) != WOLFSSL_SUCCESS)
        goto done;
    *verifyRet = wolfSSL_X509_verify_cert(ctx);
    *xerr = wolfSSL_X509_STORE_CTX_get_error(ctx);
    rc = 0;
done:
    wolfSSL_X509_STORE_CTX_free(ctx);
    wolfSSL_X509_STORE_free(store);
    wolfSSL_X509_free(xleaf);
    wolfSSL_X509_free(xca);
    return rc;
}

static hs_spec base_spec(const cert_buf* ca, const key_buf* serverKey,
    const cert_buf* serverCert)
{
    hs_spec spec;

    memset(&spec, 0, sizeof(spec));
    spec.ca = ca->der;
    spec.caSz = ca->sz;
    spec.serverCert = serverCert->der;
    spec.serverCertSz = serverCert->sz;
    spec.serverKey = serverKey->der;
    spec.serverKeySz = serverKey->sz;
    spec.clientVerifyPeer = 1;
    spec.clientMethod = wolfSSLv23_client_method;
    spec.serverMethod = wolfSSLv23_server_method;
    return spec;
}

int main(void)
{
    WC_RNG rng;
    RsaKey rootKey;
    RsaKey leafKey;
#ifdef HAVE_NC_TESTS
    RsaKey midKey;
    int midInit = 0;
#endif
    key_buf rootPriv;
    key_buf leafPriv;
    cert_buf root;
    cert_buf nameless;
    cert_buf cnMatch;
    cert_buf cnWrong;
    int hasCn = 0;
    int hasAlt = 0;
    int hasPermitted = 0;
    int rootInit = 0;
    int leafInit = 0;
    int rngInit = 0;
    hs_spec spec;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed\n");
        return 2;
    }
    if (wc_InitRng(&rng) != 0) {
        fprintf(stderr, "wc_InitRng failed\n");
        wolfSSL_Cleanup();
        return 2;
    }
    rngInit = 1;

    memset(&rootKey, 0, sizeof(rootKey));
    memset(&leafKey, 0, sizeof(leafKey));
    if (make_rsa(&rng, &rootKey, &rootPriv) != 0 ||
        make_rsa(&rng, &leafKey, &leafPriv) != 0) {
        fprintf(stderr, "RSA key generation failed\n");
        goto setup_fail;
    }
    rootInit = 1;
    leafInit = 1;

    if (build_ca(&rng, &rootKey, &root, "Test Root") != 0 ||
        build_leaf(&rng, &leafKey, &rootKey, root.der, root.sz,
            NULL, NULL, &nameless) != 0 ||
        build_leaf(&rng, &leafKey, &rootKey, root.der, root.sz,
            HOST_OK, NULL, &cnMatch) != 0 ||
        build_leaf(&rng, &leafKey, &rootKey, root.der, root.sz,
            HOST_BAD, NULL, &cnWrong) != 0) {
        fprintf(stderr, "certificate generation failed\n");
        goto setup_fail;
    }

    if (describe_cert("nameless", nameless.der, nameless.sz,
            &hasCn, &hasAlt, &hasPermitted) != 0 ||
        hasCn || hasAlt) {
        fprintf(stderr, "nameless certificate still has a CN or SAN\n");
        goto setup_fail;
    }
    if (describe_cert("cn-match", cnMatch.der, cnMatch.sz,
            &hasCn, &hasAlt, &hasPermitted) != 0 ||
        !hasCn || hasAlt) {
        fprintf(stderr, "matching certificate was not CN-only\n");
        goto setup_fail;
    }

    /* The bug: verification is on, the expected name is set only through the
     * OpenSSL set-host API, and the peer certificate has no CN and no SAN. */
    spec = base_spec(&root, &leafPriv, &nameless);
    spec.clientHost = HOST_OK;
    spec.clientMethod = wolfTLSv1_2_client_method;
    spec.serverMethod = wolfTLSv1_2_server_method;
    expect_client_mismatch(
        "tls12 set1_host rejects certificate with no CN and no SAN", &spec);

    spec = base_spec(&root, &leafPriv, &nameless);
    spec.clientHost = HOST_OK;
    spec.clientHostViaParam = 1;
    spec.clientMethod = wolfTLSv1_3_client_method;
    spec.serverMethod = wolfTLSv1_3_server_method;
    expect_client_mismatch(
        "tls13 X509_VERIFY_PARAM_set1_host rejects certificate with no CN and no SAN",
        &spec);

    /* Same certificate is acceptable when the application did not ask for a
     * hostname check. This pins the rejection above to the host check. */
    spec = base_spec(&root, &leafPriv, &nameless);
    expect_success("nameless certificate verifies when no hostname is set",
        &spec);

    spec = base_spec(&root, &leafPriv, &cnWrong);
    spec.clientHost = HOST_OK;
    expect_client_mismatch("set1_host rejects a different common name", &spec);

    spec = base_spec(&root, &leafPriv, &cnMatch);
    spec.clientHost = HOST_OK;
    expect_success("set1_host accepts a matching common name", &spec);

    spec = base_spec(&root, &leafPriv, &nameless);
    spec.clientDomain = HOST_OK;
    expect_client_mismatch(
        "wolfSSL_check_domain_name rejects certificate with no CN and no SAN",
        &spec);

    /* Server authenticating a client certificate through the same callback. */
    spec = base_spec(&root, &leafPriv, &cnMatch);
    spec.clientCert = nameless.der;
    spec.clientCertSz = nameless.sz;
    spec.clientKey = leafPriv.der;
    spec.clientKeySz = leafPriv.sz;
    spec.serverVerifyPeer = 1;
    spec.serverHost = "client.example.com";
    spec.clientVerifyPeer = 1;
    expect_server_mismatch(
        "server set1_host rejects client certificate with no CN and no SAN",
        &spec);

    {
        int verifyRet = 0;
        int xerr = 0;
        if (x509_verify_host(root.der, root.sz, nameless.der, nameless.sz,
                HOST_OK, &verifyRet, &xerr) != 0) {
            fail_msg("X509_verify_cert setup", "could not run");
        }
        else if (verifyRet == WOLFSSL_SUCCESS ||
                 xerr != WOLFSSL_X509_V_ERR_HOSTNAME_MISMATCH) {
            fprintf(stderr,
                "FAIL X509_verify_cert nameless host: ret=%d error=%d "
                "(expected failure %d)\n",
                verifyRet, xerr, WOLFSSL_X509_V_ERR_HOSTNAME_MISMATCH);
            g_failures++;
        }
        else {
            printf("PASS X509_verify_cert rejects certificate with no CN and no SAN\n");
            fflush(stdout);
        }
    }

#ifdef HAVE_NC_TESTS
    {
        cert_buf mid;
        cert_buf ncNameless;
        cert_buf ncIn;
        cert_buf ncOut;
        key_buf midPriv;

        memset(&midKey, 0, sizeof(midKey));
        if (make_rsa(&rng, &midKey, &midPriv) != 0) {
            fprintf(stderr, "intermediate key generation failed\n");
            goto setup_fail;
        }
        midInit = 1;
        {
            int step;
            step = build_constrained_ca(&rng, &midKey, &rootKey, root.der,
                root.sz, &mid);
            if (step != 0) {
                fprintf(stderr, "constrained CA build failed: %d\n", step);
                goto setup_fail;
            }
            step = build_leaf(&rng, &leafKey, &midKey, mid.der, mid.sz,
                NULL, NULL, &ncNameless);
            if (step != 0) {
                fprintf(stderr, "nameless constrained leaf failed: %d\n", step);
                goto setup_fail;
            }
            step = build_leaf(&rng, &leafKey, &midKey, mid.der, mid.sz,
                NULL, HOST_OK, &ncIn);
            if (step != 0) {
                fprintf(stderr, "in-tree SAN leaf failed: %d\n", step);
                goto setup_fail;
            }
            step = build_leaf(&rng, &leafKey, &midKey, mid.der, mid.sz,
                NULL, HOST_BAD, &ncOut);
            if (step != 0) {
                fprintf(stderr, "out-of-tree SAN leaf failed: %d\n", step);
                goto setup_fail;
            }
        }
        if (describe_cert("constrained-ca", mid.der, mid.sz,
                &hasCn, &hasAlt, &hasPermitted) != 0 || !hasPermitted) {
            fprintf(stderr, "intermediate has no permitted name constraints\n");
            goto setup_fail;
        }
        if (describe_cert("nc-nameless", ncNameless.der, ncNameless.sz,
                &hasCn, &hasAlt, &hasPermitted) != 0 || hasCn || hasAlt) {
            fprintf(stderr, "constrained leaf unexpectedly has a name\n");
            goto setup_fail;
        }

        spec = base_spec(&root, &leafPriv, &ncNameless);
        spec.chain = mid.der;
        spec.chainSz = mid.sz;
        spec.clientHost = "www.bank.example";
        spec.clientMethod = wolfTLSv1_3_client_method;
        spec.serverMethod = wolfTLSv1_3_server_method;
        expect_client_mismatch(
            "name-constrained issuer: set1_host rejects certificate with no DNS name and no CN",
            &spec);

        spec = base_spec(&root, &leafPriv, &ncIn);
        spec.chain = mid.der;
        spec.chainSz = mid.sz;
        spec.clientHost = HOST_OK;
        expect_success(
            "name-constrained issuer: DNS name inside the permitted tree is accepted",
            &spec);

        spec = base_spec(&root, &leafPriv, &ncOut);
        spec.chain = mid.der;
        spec.chainSz = mid.sz;
        spec.clientHost = HOST_BAD;
        expect_client_error(
            "name-constrained issuer: DNS name outside the permitted tree is rejected",
            &spec, ASN_NAME_INVALID_E);
    }
#else
    fprintf(stderr,
        "SKIP name-constraint cases (need WOLFSSL_CUSTOM_OID, "
        "HAVE_OID_ENCODING, WOLFSSL_ALT_NAMES)\n");
#endif

    wc_FreeRsaKey(&leafKey);
    wc_FreeRsaKey(&rootKey);
#ifdef HAVE_NC_TESTS
    if (midInit)
        wc_FreeRsaKey(&midKey);
#endif
    wc_FreeRng(&rng);
    wolfSSL_Cleanup();

    if (g_failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", g_failures);
        return 1;
    }
    printf("all nameless-host checks passed\n");
    return 0;

setup_fail:
    if (leafInit)
        wc_FreeRsaKey(&leafKey);
    if (rootInit)
        wc_FreeRsaKey(&rootKey);
#ifdef HAVE_NC_TESTS
    if (midInit)
        wc_FreeRsaKey(&midKey);
#endif
    if (rngInit)
        wc_FreeRng(&rng);
    wolfSSL_Cleanup();
    return 2;
}

/* Handshake tests for static-ECDH peer key usage.
 *
 * These tests are the spec for the missing keyAgreement check. They fail
 * while a trusted certificate whose keyUsage extension omits keyAgreement is
 * still accepted for a static ECDH suite, and they pass once that certificate
 * is rejected and the cases below still succeed.
 *
 * Build and run (the binary is expected to exit 1 until the check is fixed):
 *
 *   ./autogen.sh
 *   ./configure --enable-certgen --enable-certext --enable-keygen \
 *       --disable-examples --disable-crypttests CFLAGS="-DWOLFSSL_STATIC_DH -O2"
 *   make -j
 *   gcc -o static_ecdh_keyusage_test tests/static_ecdh_keyusage_test.c \
 *       -I. -Wall -Wextra -O2 \
 *       -Lsrc/.libs -lwolfssl -Wl,-rpath,"$PWD/src/.libs" -lm
 *   ./static_ecdh_keyusage_test
 *
 *
 * Required behavior, when the peer certificate contains a keyUsage extension:
 *
 *   - Static ECDH (ECDH_ECDSA and ECDH_RSA): the certificate public key is the
 *     key-agreement key. keyAgreement is required. digitalSignature is not,
 *     because that key does not sign the handshake.
 *   - The same static ECDH suite with client authentication: the client
 *     certificate signs CertificateVerify. digitalSignature is required.
 *     keyAgreement is not, because the client key is not the agreement key.
 *   - Ephemeral ECDHE_ECDSA: the server certificate signs ServerKeyExchange.
 *     digitalSignature is required. keyAgreement alone is not enough.
 *
 * Every static ECDH suite in src/keys.c sets static_ecdh and either
 * ecc_dsa_sa_algo or rsa_sa_algo, and every peer certificate is judged by the
 * one check in ProcessPeerCerts. AES-128-CBC-SHA, AES-128-CBC-SHA256, and
 * AES-128-GCM-SHA256 cover both signature-algorithm flags and both CBC and
 * AEAD bulk ciphers. The other static ECDH suites (AES-256, SHA-384, 3DES,
 * RC4) share that same check and are not given their own handshake.
 */

#include <wolfssl/options.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DER_MAX 4096
#define KEY_DER_MAX 512

enum {
    EXPECT_REJECT = 0,
    EXPECT_ACCEPT = 1
};

typedef struct Material {
    WC_RNG rng;
    ecc_key caEcc;
    ecc_key srv;
    ecc_key cli;
    RsaKey caRsa;
    byte caEccDer[DER_MAX];
    byte caRsaDer[DER_MAX];
    byte srvKeyDer[KEY_DER_MAX];
    byte cliKeyDer[KEY_DER_MAX];
    int caEccDerSz;
    int caRsaDerSz;
    int srvKeyDerSz;
    int cliKeyDerSz;
    int haveRsa;
} Material;

typedef struct Case {
    const char* name;
    const char* cipher;       /* name passed to set_cipher_list */
    const char* iana;         /* wolfSSL_get_cipher() result */
    int rsaIssuer;           /* 1: RSA-signed ECC cert (ECDH_RSA) */
    word16 serverKu;
    byte serverEku;
    int clientAuth;
    word16 clientKu;
    byte clientEku;
    int expect;
} Case;

static int g_failed;

static void format_err(int err, char* buf, size_t bufSz)
{
    if (bufSz == 0)
        return;
    wolfSSL_ERR_error_string((unsigned long)err, buf);
    buf[bufSz - 1] = '\0';
}

static void set_name(CertName* name, const char* cn)
{
    strncpy(name->country, "US", CTC_NAME_SIZE - 1);
    strncpy(name->org, "wolfssl-keyusage-test", CTC_NAME_SIZE - 1);
    strncpy(name->commonName, cn, CTC_NAME_SIZE - 1);
}

static int export_ecc_key(ecc_key* key, byte* der, int* derSz)
{
    int sz = wc_EccPrivateKeyToDer(key, der, KEY_DER_MAX);
    if (sz <= 0)
        return sz == 0 ? -1 : sz;
    *derSz = sz;
    return 0;
}

/* Confirm the encoded leaf really carries the keyUsage bits the case claims. */
static int assert_leaf_usage(const char* name, const byte* der, int derSz,
    word16 ku, byte eku)
{
    DecodedCert decoded;
    int ret;

    wc_InitDecodedCert(&decoded, der, (word32)derSz, NULL);
    ret = wc_ParseCert(&decoded, CERT_TYPE, NO_VERIFY, NULL);
    if (ret != 0) {
        fprintf(stderr, "SETUP %s: leaf did not parse: %d\n", name, ret);
        wc_FreeDecodedCert(&decoded);
        return -1;
    }
    if (!decoded.extKeyUsageSet || decoded.extKeyUsage != ku) {
        fprintf(stderr, "SETUP %s: keyUsage set=%d got=0x%x want=0x%x\n",
            name, decoded.extKeyUsageSet, decoded.extKeyUsage, ku);
        wc_FreeDecodedCert(&decoded);
        return -1;
    }
    if (!decoded.extExtKeyUsageSet || decoded.extExtKeyUsage != eku) {
        fprintf(stderr, "SETUP %s: extKeyUsage set=%d got=0x%x want=0x%x\n",
            name, decoded.extExtKeyUsageSet, decoded.extExtKeyUsage, eku);
        wc_FreeDecodedCert(&decoded);
        return -1;
    }
    if ((ku & KEYUSE_KEY_AGREE) == 0 &&
            (decoded.extKeyUsage & KEYUSE_KEY_AGREE) != 0) {
        fprintf(stderr, "SETUP %s: keyAgreement bit was set\n", name);
        wc_FreeDecodedCert(&decoded);
        return -1;
    }
    wc_FreeDecodedCert(&decoded);
    return 0;
}

static int make_ecc_ca(Material* m)
{
    Cert cert;
    int body;
    int sz;

    if (wc_ecc_init(&m->caEcc) != 0 ||
            wc_ecc_make_key(&m->rng, 32, &m->caEcc) != 0)
        return -1;
    if (wc_InitCert(&cert) != 0)
        return -1;
    set_name(&cert.subject, "static-ecdh-ca");
    cert.isCA = 1;
    cert.sigType = CTC_SHA256wECDSA;
    cert.keyUsage = KEYUSE_KEY_CERT_SIGN | KEYUSE_CRL_SIGN;
    if (wc_SetSubjectKeyIdFromPublicKey_ex(&cert, ECC_TYPE, &m->caEcc) != 0)
        return -1;
    body = wc_MakeCert(&cert, m->caEccDer, DER_MAX, NULL, &m->caEcc, &m->rng);
    if (body < 0)
        return body;
    sz = wc_SignCert(cert.bodySz, cert.sigType, m->caEccDer, DER_MAX,
        NULL, &m->caEcc, &m->rng);
    if (sz < 0)
        return sz;
    m->caEccDerSz = sz;
    return 0;
}

static int make_rsa_ca(Material* m)
{
    Cert cert;
    int body;
    int sz;

    if (wc_InitRsaKey(&m->caRsa, NULL) != 0 ||
            wc_MakeRsaKey(&m->caRsa, 2048, 65537, &m->rng) != 0)
        return -1;
    m->haveRsa = 1;
    if (wc_InitCert(&cert) != 0)
        return -1;
    set_name(&cert.subject, "static-ecdh-rsa-ca");
    cert.isCA = 1;
    cert.sigType = CTC_SHA256wRSA;
    cert.keyUsage = KEYUSE_KEY_CERT_SIGN | KEYUSE_CRL_SIGN;
    if (wc_SetSubjectKeyIdFromPublicKey_ex(&cert, RSA_TYPE, &m->caRsa) != 0)
        return -1;
    body = wc_MakeCert(&cert, m->caRsaDer, DER_MAX, &m->caRsa, NULL, &m->rng);
    if (body < 0)
        return body;
    sz = wc_SignCert(cert.bodySz, cert.sigType, m->caRsaDer, DER_MAX,
        &m->caRsa, NULL, &m->rng);
    if (sz < 0)
        return sz;
    m->caRsaDerSz = sz;
    return 0;
}

static int make_leaf(Material* m, ecc_key* subject, int rsaIssuer,
    word16 ku, byte eku, const char* cn, byte* der, int* derSz)
{
    Cert cert;
    int body;
    int sz;
    const byte* issuerDer;
    int issuerDerSz;

    if (wc_InitCert(&cert) != 0)
        return -1;
    set_name(&cert.subject, cn);
    cert.isCA = 0;
    cert.keyUsage = ku;
    cert.extKeyUsage = eku;
    if (wc_SetSubjectKeyIdFromPublicKey_ex(&cert, ECC_TYPE, subject) != 0)
        return -1;
    if (rsaIssuer) {
        cert.sigType = CTC_SHA256wRSA;
        issuerDer = m->caRsaDer;
        issuerDerSz = m->caRsaDerSz;
        if (wc_SetAuthKeyIdFromPublicKey_ex(&cert, RSA_TYPE, &m->caRsa) != 0)
            return -1;
    }
    else {
        cert.sigType = CTC_SHA256wECDSA;
        issuerDer = m->caEccDer;
        issuerDerSz = m->caEccDerSz;
        if (wc_SetAuthKeyIdFromPublicKey_ex(&cert, ECC_TYPE, &m->caEcc) != 0)
            return -1;
    }
    if (wc_SetIssuerBuffer(&cert, issuerDer, issuerDerSz) < 0)
        return -1;
    body = wc_MakeCert(&cert, der, DER_MAX, NULL, subject, &m->rng);
    if (body < 0)
        return body;
    if (rsaIssuer)
        sz = wc_SignCert(cert.bodySz, cert.sigType, der, DER_MAX,
            &m->caRsa, NULL, &m->rng);
    else
        sz = wc_SignCert(cert.bodySz, cert.sigType, der, DER_MAX,
            NULL, &m->caEcc, &m->rng);
    if (sz < 0)
        return sz;
    *derSz = sz;
    return assert_leaf_usage(cn, der, sz, ku, eku);
}

static int io_done(int n, int err)
{
    if (n == WOLFSSL_SUCCESS)
        return 1;
    if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE)
        return 0;
    return -1;
}

/* Drive both ends until the handshake finishes or one side reports a fatal
 * error. Returns 0 on success, -1 on a TLS error, -2 if it stops making
 * progress. */
static int drive_handshake(WOLFSSL* server, WOLFSSL* client,
    int* serverErr, int* clientErr)
{
    int i;

    *serverErr = 0;
    *clientErr = 0;
    for (i = 0; i < 80; i++) {
        int sr = wolfSSL_accept(server);
        int se = wolfSSL_get_error(server, sr);
        int cr = wolfSSL_connect(client);
        int ce = wolfSSL_get_error(client, cr);
        int sd = io_done(sr, se);
        int cd = io_done(cr, ce);

        if (sd < 0 || cd < 0) {
            *serverErr = se;
            *clientErr = ce;
            return -1;
        }
        if (sd == 1 && cd == 1)
            return 0;
    }
    *serverErr = wolfSSL_get_error(server, 0);
    *clientErr = wolfSSL_get_error(client, 0);
    return -2;
}

static int write_all(WOLFSSL* ssl, const char* buf, int sz)
{
    int off = 0;
    int spins = 0;

    while (off < sz && spins++ < 40) {
        int n = wolfSSL_write(ssl, buf + off, sz - off);
        int err;
        if (n > 0) {
            off += n;
            continue;
        }
        err = wolfSSL_get_error(ssl, n);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE)
            continue;
        return err;
    }
    return off == sz ? 0 : -1;
}

static int read_all(WOLFSSL* ssl, char* buf, int sz)
{
    int off = 0;
    int spins = 0;

    while (off < sz && spins++ < 40) {
        int n = wolfSSL_read(ssl, buf + off, sz - off);
        int err;
        if (n > 0) {
            off += n;
            continue;
        }
        err = wolfSSL_get_error(ssl, n);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE)
            continue;
        return err;
    }
    return off == sz ? 0 : -1;
}

/* Exchange application data in both directions. A completed handshake is not
 * enough: the static certificate key has to be the key that protects traffic. */
static int exchange(WOLFSSL* server, WOLFSSL* client, const char* tag)
{
    char cmsg[64];
    char smsg[64];
    char got[64];
    int clen;
    int slen;

    clen = snprintf(cmsg, sizeof cmsg, "client-traffic-%s", tag);
    slen = snprintf(smsg, sizeof smsg, "server-traffic-%s", tag);
    if (clen <= 0 || slen <= 0 || clen >= (int)sizeof cmsg ||
            slen >= (int)sizeof smsg)
        return -1;
    if (write_all(client, cmsg, clen) != 0)
        return -1;
    if (read_all(server, got, clen) != 0)
        return -1;
    if (memcmp(got, cmsg, (size_t)clen) != 0)
        return -1;
    if (write_all(server, smsg, slen) != 0)
        return -1;
    if (read_all(client, got, slen) != 0)
        return -1;
    if (memcmp(got, smsg, (size_t)slen) != 0)
        return -1;
    return 0;
}

static int load_end(WOLFSSL_CTX* ctx, const byte* cert, int certSz,
    const byte* key, int keySz, const byte* ca, int caSz, int verifyPeer)
{
    if (wolfSSL_CTX_load_verify_buffer(ctx, ca, caSz, WOLFSSL_FILETYPE_ASN1)
            != WOLFSSL_SUCCESS)
        return -1;
    if (wolfSSL_CTX_use_certificate_buffer(ctx, cert, certSz,
            WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
        return -1;
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, key, keySz,
            WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
        return -1;
    if (wolfSSL_CTX_check_private_key(ctx) != 1)
        return -1;
    wolfSSL_CTX_set_verify(ctx, verifyPeer, NULL);
    return 0;
}

static void run_case(Material* m, const Case* cs)
{
    byte serverDer[DER_MAX];
    byte clientDer[DER_MAX];
    int serverDerSz = 0;
    int clientDerSz = 0;
    const byte* caDer;
    int caDerSz;
    WOLFSSL_CTX* sctx = NULL;
    WOLFSSL_CTX* cctx = NULL;
    WOLFSSL* server = NULL;
    WOLFSSL* client = NULL;
    int fds[2] = {-1, -1};
    int serverErr = 0;
    int clientErr = 0;
    int hs;
    int failed = 0;
    const char* cipher = NULL;
    char serverMsg[WOLFSSL_MAX_ERROR_SZ];
    char clientMsg[WOLFSSL_MAX_ERROR_SZ];

    caDer = cs->rsaIssuer ? m->caRsaDer : m->caEccDer;
    caDerSz = cs->rsaIssuer ? m->caRsaDerSz : m->caEccDerSz;

    if (make_leaf(m, &m->srv, cs->rsaIssuer, cs->serverKu, cs->serverEku,
            "server.example", serverDer, &serverDerSz) != 0) {
        fprintf(stderr, "FAIL %s: could not build server certificate\n",
            cs->name);
        g_failed++;
        return;
    }
    if (cs->clientAuth &&
            make_leaf(m, &m->cli, 0, cs->clientKu, cs->clientEku,
                "client.example", clientDer, &clientDerSz) != 0) {
        fprintf(stderr, "FAIL %s: could not build client certificate\n",
            cs->name);
        g_failed++;
        return;
    }

    sctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
    cctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (sctx == NULL || cctx == NULL) {
        fprintf(stderr, "FAIL %s: CTX_new failed\n", cs->name);
        failed = 1;
        goto done;
    }
    if (wolfSSL_CTX_set_cipher_list(sctx, cs->cipher) != WOLFSSL_SUCCESS ||
            wolfSSL_CTX_set_cipher_list(cctx, cs->cipher) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "FAIL %s: cipher %s is not available\n",
            cs->name, cs->cipher);
        failed = 1;
        goto done;
    }
    if (load_end(sctx, serverDer, serverDerSz, m->srvKeyDer, m->srvKeyDerSz,
            caDer, caDerSz,
            cs->clientAuth
                ? (WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT)
                : WOLFSSL_VERIFY_NONE) != 0) {
        fprintf(stderr, "FAIL %s: server credentials rejected\n", cs->name);
        failed = 1;
        goto done;
    }
    if (cs->clientAuth) {
        if (load_end(cctx, clientDer, clientDerSz, m->cliKeyDer,
                m->cliKeyDerSz, caDer, caDerSz, WOLFSSL_VERIFY_PEER) != 0) {
            fprintf(stderr, "FAIL %s: client credentials rejected\n",
                cs->name);
            failed = 1;
            goto done;
        }
    }
    else if (wolfSSL_CTX_load_verify_buffer(cctx, caDer, caDerSz,
            WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "FAIL %s: client could not load CA\n", cs->name);
        failed = 1;
        goto done;
    }
    else {
        wolfSSL_CTX_set_verify(cctx, WOLFSSL_VERIFY_PEER, NULL);
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        fprintf(stderr, "FAIL %s: socketpair: %s\n", cs->name, strerror(errno));
        failed = 1;
        goto done;
    }
    if (fcntl(fds[0], F_SETFL, fcntl(fds[0], F_GETFL, 0) | O_NONBLOCK) != 0 ||
            fcntl(fds[1], F_SETFL, fcntl(fds[1], F_GETFL, 0) | O_NONBLOCK) != 0) {
        fprintf(stderr, "FAIL %s: could not set nonblocking\n", cs->name);
        failed = 1;
        goto done;
    }

    server = wolfSSL_new(sctx);
    client = wolfSSL_new(cctx);
    if (server == NULL || client == NULL ||
            wolfSSL_set_fd(server, fds[0]) != WOLFSSL_SUCCESS ||
            wolfSSL_set_fd(client, fds[1]) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "FAIL %s: could not bind sockets\n", cs->name);
        failed = 1;
        goto done;
    }

    hs = drive_handshake(server, client, &serverErr, &clientErr);
    format_err(serverErr, serverMsg, sizeof serverMsg);
    format_err(clientErr, clientMsg, sizeof clientMsg);
    cipher = wolfSSL_get_cipher(server);
    if (cs->expect == EXPECT_ACCEPT) {
        if (hs != 0) {
            fprintf(stderr,
                "FAIL %s: handshake rejected (server %d %s, client %d %s)\n",
                cs->name, serverErr, serverMsg, clientErr, clientMsg);
            failed = 1;
        }
        else if (cipher == NULL || strcmp(cipher, cs->iana) != 0) {
            fprintf(stderr, "FAIL %s: negotiated %s, wanted %s\n",
                cs->name, cipher != NULL ? cipher : "(null)", cs->iana);
            failed = 1;
        }
        else if (exchange(server, client, cs->name) != 0) {
            fprintf(stderr,
                "FAIL %s: handshake finished but application data did not "
                "round-trip on %s\n",
                cs->name, cipher);
            failed = 1;
        }
        else {
            fprintf(stderr, "PASS %s: accepted %s and exchanged traffic\n",
                cs->name, cipher);
        }
    }
    else if (hs == 0) {
        fprintf(stderr,
            "FAIL %s: handshake accepted %s (key usage was not enforced)\n",
            cs->name, cipher != NULL ? cipher : "(null)");
        failed = 1;
    }
    else if (hs == -2) {
        fprintf(stderr, "FAIL %s: handshake made no progress\n", cs->name);
        failed = 1;
    }
    else {
        fprintf(stderr, "PASS %s: rejected (server %d %s, client %d %s)\n",
            cs->name, serverErr, serverMsg, clientErr, clientMsg);
    }

done:
    if (server != NULL)
        wolfSSL_free(server);
    if (client != NULL)
        wolfSSL_free(client);
    if (sctx != NULL)
        wolfSSL_CTX_free(sctx);
    if (cctx != NULL)
        wolfSSL_CTX_free(cctx);
    if (fds[0] >= 0)
        close(fds[0]);
    if (fds[1] >= 0)
        close(fds[1]);
    if (failed)
        g_failed++;
}

int main(void)
{
    Material m;
    static const Case cases[] = {
        /* Attack path: keyUsage is present and contains neither
         * keyAgreement nor digitalSignature. Static ECDH ECDSA must reject. */
        { "ecdh-ecdsa-sha256-neither", "ECDH-ECDSA-AES128-SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", 0,
            KEYUSE_DATA_ENCIPHER, EXTKEYUSE_SERVER_AUTH, 0, 0, 0,
            EXPECT_REJECT },
        { "ecdh-ecdsa-gcm-neither", "ECDH-ECDSA-AES128-GCM-SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", 0,
            KEYUSE_DATA_ENCIPHER, EXTKEYUSE_SERVER_AUTH, 0, 0, 0,
            EXPECT_REJECT },
        { "ecdh-ecdsa-sha-neither", "ECDH-ECDSA-AES128-SHA",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", 0,
            KEYUSE_DATA_ENCIPHER, EXTKEYUSE_SERVER_AUTH, 0, 0, 0,
            EXPECT_REJECT },
        /* digitalSignature without keyAgreement is still unfit for agreement. */
        { "ecdh-ecdsa-sha256-sig-only", "ECDH-ECDSA-AES128-SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", 0,
            KEYUSE_DIGITAL_SIG, EXTKEYUSE_SERVER_AUTH, 0, 0, 0,
            EXPECT_REJECT },
        /* keyAgreement, no digitalSignature: the static key does not sign. */
        { "ecdh-ecdsa-sha256-agree", "ECDH-ECDSA-AES128-SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", 0,
            KEYUSE_KEY_AGREE, EXTKEYUSE_SERVER_AUTH, 0, 0, 0,
            EXPECT_ACCEPT },
        { "ecdh-ecdsa-gcm-agree", "ECDH-ECDSA-AES128-GCM-SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", 0,
            KEYUSE_KEY_AGREE, EXTKEYUSE_SERVER_AUTH, 0, 0, 0,
            EXPECT_ACCEPT },
        { "ecdh-ecdsa-sha-agree", "ECDH-ECDSA-AES128-SHA",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", 0,
            KEYUSE_KEY_AGREE, EXTKEYUSE_SERVER_AUTH, 0, 0, 0,
            EXPECT_ACCEPT },
        /* ECDH_RSA uses the same agreement key. The existing digitalSignature
         * test does not look at keyAgreement. */
        { "ecdh-rsa-sha256-sig-only", "ECDH-RSA-AES128-SHA256",
            "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", 1,
            KEYUSE_DIGITAL_SIG, EXTKEYUSE_SERVER_AUTH, 0, 0, 0,
            EXPECT_REJECT },
        { "ecdh-rsa-sha256-neither", "ECDH-RSA-AES128-SHA256",
            "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", 1,
            KEYUSE_DATA_ENCIPHER, EXTKEYUSE_SERVER_AUTH, 0, 0, 0,
            EXPECT_REJECT },
        { "ecdh-rsa-sha256-agree", "ECDH-RSA-AES128-SHA256",
            "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", 1,
            KEYUSE_KEY_AGREE, EXTKEYUSE_SERVER_AUTH, 0, 0, 0,
            EXPECT_ACCEPT },
        /* Client certificate on a static ECDH suite signs; it does not agree. */
        { "ecdh-ecdsa-client-agree-only", "ECDH-ECDSA-AES128-SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", 0,
            KEYUSE_KEY_AGREE, EXTKEYUSE_SERVER_AUTH, 1,
            KEYUSE_KEY_AGREE, EXTKEYUSE_CLIENT_AUTH, EXPECT_REJECT },
        { "ecdh-ecdsa-client-sig-only", "ECDH-ECDSA-AES128-SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", 0,
            KEYUSE_KEY_AGREE, EXTKEYUSE_SERVER_AUTH, 1,
            KEYUSE_DIGITAL_SIG, EXTKEYUSE_CLIENT_AUTH, EXPECT_ACCEPT },
        /* Ephemeral ECDHE still requires digitalSignature on the signing key. */
        { "ecdhe-ecdsa-sig", "ECDHE-ECDSA-AES128-SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0,
            KEYUSE_DIGITAL_SIG, EXTKEYUSE_SERVER_AUTH, 0, 0, 0,
            EXPECT_ACCEPT },
        { "ecdhe-ecdsa-agree-only", "ECDHE-ECDSA-AES128-SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0,
            KEYUSE_KEY_AGREE, EXTKEYUSE_SERVER_AUTH, 0, 0, 0,
            EXPECT_REJECT },
    };
    size_t i;

    memset(&m, 0, sizeof m);
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed\n");
        return 2;
    }
    if (wc_InitRng(&m.rng) != 0 ||
            wc_ecc_init(&m.srv) != 0 || wc_ecc_init(&m.cli) != 0 ||
            wc_ecc_make_key(&m.rng, 32, &m.srv) != 0 ||
            wc_ecc_make_key(&m.rng, 32, &m.cli) != 0 ||
            export_ecc_key(&m.srv, m.srvKeyDer, &m.srvKeyDerSz) != 0 ||
            export_ecc_key(&m.cli, m.cliKeyDer, &m.cliKeyDerSz) != 0 ||
            make_ecc_ca(&m) != 0 || make_rsa_ca(&m) != 0) {
        fprintf(stderr, "could not generate keys and CAs\n");
        wolfSSL_Cleanup();
        return 2;
    }

    for (i = 0; i < sizeof cases / sizeof cases[0]; i++)
        run_case(&m, &cases[i]);

    wc_ecc_free(&m.srv);
    wc_ecc_free(&m.cli);
    wc_ecc_free(&m.caEcc);
    if (m.haveRsa)
        wc_FreeRsaKey(&m.caRsa);
    wc_FreeRng(&m.rng);
    wolfSSL_Cleanup();

    if (g_failed != 0) {
        fprintf(stderr, "%d case(s) failed\n", g_failed);
        return 1;
    }
    printf("all static ECDH key-usage cases passed\n");
    return 0;
}

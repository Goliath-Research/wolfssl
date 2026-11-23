/* tests/rpk_unverified_spki.c
 *
 * Spec for the raw-public-key certificate-verification bypass.
 *
 * These checks fail while the vulnerability is present and pass once
 * verification refuses an unpinned SubjectPublicKeyInfo. They exercise the
 * public APIs an application uses to decide trust:
 *   wolfSSL_CertManagerVerifyBuffer
 *   wolfSSL_CertManagerVerify
 *   wolfSSL_X509_verify_cert
 *
 * Build (from the repository root, after configuring with raw public key
 * support and OpenSSL extra):
 *   make -C src -j"$(nproc)"
 *   gcc -o tests/rpk_unverified_spki tests/rpk_unverified_spki.c \
 *       -I. -DWOLFSSL_USE_OPTIONS_H \
 *       src/.libs/libwolfssl.a -lm -pthread
 *   ./tests/rpk_unverified_spki
 *
 * The program returns 0 only when every untrusted input is rejected and the
 * legitimate controls still verify.
 */

#include <wolfssl/options.h>

#ifndef HAVE_RPK
#error "This test must be built against a wolfSSL configured with raw public key support"
#endif
#ifndef OPENSSL_EXTRA
#error "This test must be built against a wolfSSL configured with --enable-opensslextra"
#endif

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures = 0;

static void expect_trusted(const char* name, int ret)
{
    if (ret == WOLFSSL_SUCCESS) {
        printf("PASS  %-52s trusted (ret=%d)\n", name, ret);
    }
    else {
        printf("FAIL  %-52s expected trust, ret=%d\n", name, ret);
        g_failures++;
    }
}

static void expect_untrusted(const char* name, int ret)
{
    if (ret == WOLFSSL_SUCCESS) {
        printf("FAIL  %-52s reported trusted (ret=%d)\n", name, ret);
        g_failures++;
    }
    else {
        printf("PASS  %-52s rejected (ret=%d)\n", name, ret);
    }
}

static int read_file(const char* path, unsigned char** out, long* outSz)
{
    FILE* f;
    long sz;
    unsigned char* buf;

    *out = NULL;
    *outSz = 0;
    f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    sz = ftell(f);
    if (sz <= 0) {
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    buf = (unsigned char*)malloc((size_t)sz);
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
    *outSz = sz;
    return 0;
}

/* Confirm the buffer is a complete SubjectPublicKeyInfo for this key type.
 * The private half is discarded by the caller before verification. */
static int ecc_spki_ok(const unsigned char* spki, int spkiSz)
{
    ecc_key key;
    word32 idx = 0;
    int ret;

    if (wc_ecc_init(&key) != 0) {
        return 0;
    }
    ret = wc_EccPublicKeyDecode(spki, &idx, &key, (word32)spkiSz);
    wc_ecc_free(&key);
    return ret == 0 && idx == (word32)spkiSz;
}

static int rsa_spki_ok(const unsigned char* spki, int spkiSz)
{
    RsaKey key;
    word32 idx = 0;
    int ret;

    if (wc_InitRsaKey(&key, NULL) != 0) {
        return 0;
    }
    ret = wc_RsaPublicKeyDecode(spki, &idx, &key, (word32)spkiSz);
    wc_FreeRsaKey(&key);
    return ret == 0 && idx == (word32)spkiSz;
}

static int make_ecc_spki(WC_RNG* rng, unsigned char* spki, int cap)
{
    ecc_key key;
    int sz = -1;

    if (wc_ecc_init(&key) != 0) {
        return -1;
    }
    if (wc_ecc_make_key(rng, 32, &key) == 0) {
        sz = wc_EccPublicKeyToDer(&key, spki, (word32)cap, 1);
    }
    wc_ecc_free(&key);
    if (sz <= 0 || !ecc_spki_ok(spki, sz)) {
        return -1;
    }
    return sz;
}

static int make_rsa_spki(WC_RNG* rng, unsigned char* spki, int cap)
{
    RsaKey key;
    int sz = -1;

    if (wc_InitRsaKey(&key, NULL) != 0) {
        return -1;
    }
    /* Public exponent only. The private half is freed before any verify call. */
    if (wc_MakeRsaKey(&key, 2048, 65537L, rng) == 0) {
        sz = wc_RsaKeyToPublicDer(&key, spki, (word32)cap);
    }
    wc_FreeRsaKey(&key);
    if (sz <= 0 || !rsa_spki_ok(spki, sz)) {
        return -1;
    }
    return sz;
}

/* PEM framing an application would accept as a certificate file. The body
 * is only the SubjectPublicKeyInfo. */
static int spki_as_pem_certificate(const unsigned char* der, int derSz,
                                   unsigned char* pem, int cap, int* pemSz)
{
    unsigned char b64[2048];
    word32 b64Sz = sizeof(b64);
    const char* hdr = "-----BEGIN CERTIFICATE-----\n";
    const char* ftr = "\n-----END CERTIFICATE-----\n";
    int hdrLen;
    int ftrLen;
    int total;

    if (Base64_Encode(der, (word32)derSz, b64, &b64Sz) != 0) {
        return -1;
    }
    hdrLen = (int)strlen(hdr);
    ftrLen = (int)strlen(ftr);
    total = hdrLen + (int)b64Sz + ftrLen;
    if (total > cap) {
        return -1;
    }
    memcpy(pem, hdr, (size_t)hdrLen);
    memcpy(pem + hdrLen, b64, b64Sz);
    memcpy(pem + hdrLen + b64Sz, ftr, (size_t)ftrLen);
    *pemSz = total;
    return 0;
}

static int store_verify(WOLFSSL_X509_STORE* store, const unsigned char* der,
                        long derSz)
{
    const unsigned char* p = der;
    WOLFSSL_X509* cert;
    WOLFSSL_X509_STORE_CTX* ctx;
    int ret;

    cert = wolfSSL_d2i_X509(NULL, &p, (int)derSz);
    if (cert == NULL) {
        /* Parsing rejected the input, so it is not a trusted certificate. */
        return WOLFSSL_FAILURE;
    }
    ctx = wolfSSL_X509_STORE_CTX_new();
    if (ctx == NULL) {
        wolfSSL_X509_free(cert);
        return WOLFSSL_FATAL_ERROR;
    }
    if (wolfSSL_X509_STORE_CTX_init(ctx, store, cert, NULL) != WOLFSSL_SUCCESS) {
        wolfSSL_X509_STORE_CTX_free(ctx);
        wolfSSL_X509_free(cert);
        return WOLFSSL_FATAL_ERROR;
    }
    ret = wolfSSL_X509_verify_cert(ctx);
    wolfSSL_X509_STORE_CTX_free(ctx);
    wolfSSL_X509_free(cert);
    return ret;
}

int main(void)
{
    WOLFSSL_CERT_MANAGER* cm = NULL;
    WOLFSSL_CERT_MANAGER* empty = NULL;
    WOLFSSL_X509_STORE* store = NULL;
    WOLFSSL_X509* ca = NULL;
    WC_RNG rng;
    unsigned char eccSpki[512];
    unsigned char rsaSpki[1024];
    unsigned char pem[2048];
    unsigned char* serverDer = NULL;
    unsigned char* clientDer = NULL;
    unsigned char* eccCertDer = NULL;
    unsigned char garbage[32];
    long serverDerSz = 0;
    long clientDerSz = 0;
    long eccCertDerSz = 0;
    int eccSz;
    int rsaSz;
    int pemSz = 0;
    int ret;
    const char* spkiPath = "tests/rpk_attacker_spki.der";
    FILE* spkiFile;

    memset(garbage, 0xA5, sizeof(garbage));

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed\n");
        return 2;
    }
    if (wc_InitRng(&rng) != 0) {
        fprintf(stderr, "wc_InitRng failed\n");
        wolfSSL_Cleanup();
        return 2;
    }

    eccSz = make_ecc_spki(&rng, eccSpki, (int)sizeof(eccSpki));
    rsaSz = make_rsa_spki(&rng, rsaSpki, (int)sizeof(rsaSpki));
    wc_FreeRng(&rng);
    if (eccSz < 0 || rsaSz < 0) {
        fprintf(stderr, "failed to generate a subject public key\n");
        wolfSSL_Cleanup();
        return 2;
    }
    if (spki_as_pem_certificate(eccSpki, eccSz, pem, (int)sizeof(pem),
                                &pemSz) != 0) {
        fprintf(stderr, "failed to PEM-encode the subject public key\n");
        wolfSSL_Cleanup();
        return 2;
    }

    if (read_file("certs/server-cert.der", &serverDer, &serverDerSz) != 0 ||
        read_file("certs/client-cert.der", &clientDer, &clientDerSz) != 0 ||
        read_file("certs/server-ecc.der", &eccCertDer, &eccCertDerSz) != 0) {
        fprintf(stderr, "failed to read test certificates\n");
        wolfSSL_Cleanup();
        return 2;
    }

    cm = wolfSSL_CertManagerNew();
    empty = wolfSSL_CertManagerNew();
    if (cm == NULL || empty == NULL) {
        fprintf(stderr, "CertManagerNew failed\n");
        wolfSSL_Cleanup();
        return 2;
    }
    if (wolfSSL_CertManagerLoadCA(cm, "certs/ca-cert.pem", NULL) !=
            WOLFSSL_SUCCESS) {
        fprintf(stderr, "failed to load trust anchor certs/ca-cert.pem\n");
        wolfSSL_Cleanup();
        return 2;
    }

    /* Controls: the same manager trusts the leaf issued by that anchor and
     * rejects other certificates and garbage. */
    expect_trusted("certmanager trusted leaf DER",
        wolfSSL_CertManagerVerifyBuffer(cm, serverDer, serverDerSz,
            WOLFSSL_FILETYPE_ASN1));
    expect_trusted("certmanager trusted leaf file",
        wolfSSL_CertManagerVerify(cm, "certs/server-cert.pem",
            WOLFSSL_FILETYPE_PEM));
    expect_untrusted("certmanager unrelated self-signed cert",
        wolfSSL_CertManagerVerifyBuffer(cm, clientDer, clientDerSz,
            WOLFSSL_FILETYPE_ASN1));
    expect_untrusted("certmanager cert from a different anchor",
        wolfSSL_CertManagerVerifyBuffer(cm, eccCertDer, eccCertDerSz,
            WOLFSSL_FILETYPE_ASN1));
    expect_untrusted("certmanager garbage",
        wolfSSL_CertManagerVerifyBuffer(cm, garbage, (long)sizeof(garbage),
            WOLFSSL_FILETYPE_ASN1));
    expect_untrusted("certmanager empty manager, real leaf",
        wolfSSL_CertManagerVerifyBuffer(empty, serverDer, serverDerSz,
            WOLFSSL_FILETYPE_ASN1));

    /* Attacker input: a SubjectPublicKeyInfo for a key generated in this
     * process. No issuer, no signature, and the key is not the loaded anchor. */
    expect_untrusted("certmanager attacker ECC raw public key",
        wolfSSL_CertManagerVerifyBuffer(cm, eccSpki, eccSz,
            WOLFSSL_FILETYPE_ASN1));
    expect_untrusted("certmanager attacker RSA raw public key",
        wolfSSL_CertManagerVerifyBuffer(cm, rsaSpki, rsaSz,
            WOLFSSL_FILETYPE_ASN1));
    expect_untrusted("certmanager attacker ECC raw public key PEM",
        wolfSSL_CertManagerVerifyBuffer(cm, pem, pemSz, WOLFSSL_FILETYPE_PEM));
    expect_untrusted("certmanager attacker ECC raw public key, no anchors",
        wolfSSL_CertManagerVerifyBuffer(empty, eccSpki, eccSz,
            WOLFSSL_FILETYPE_ASN1));

    spkiFile = fopen(spkiPath, "wb");
    if (spkiFile == NULL ||
            fwrite(eccSpki, 1, (size_t)eccSz, spkiFile) != (size_t)eccSz) {
        fprintf(stderr, "failed to write %s\n", spkiPath);
        if (spkiFile != NULL) {
            fclose(spkiFile);
        }
        wolfSSL_Cleanup();
        return 2;
    }
    fclose(spkiFile);
    ret = wolfSSL_CertManagerVerify(cm, spkiPath, WOLFSSL_FILETYPE_ASN1);
    remove(spkiPath);
    expect_untrusted("certmanager attacker ECC raw public key file", ret);

    /* OpenSSL-compat store path. wolfSSL_X509_verify_cert calls
     * wolfSSL_CertManagerVerifyBuffer on the certificate bytes. */
    ca = wolfSSL_X509_load_certificate_file("certs/ca-cert.pem",
            WOLFSSL_FILETYPE_PEM);
    store = wolfSSL_X509_STORE_new();
    if (ca == NULL || store == NULL ||
            wolfSSL_X509_STORE_add_cert(store, ca) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "failed to build X509 store\n");
        wolfSSL_Cleanup();
        return 2;
    }
    expect_trusted("x509 store trusted leaf",
        store_verify(store, serverDer, serverDerSz));
    expect_untrusted("x509 store unrelated self-signed cert",
        store_verify(store, clientDer, clientDerSz));
    expect_untrusted("x509 store attacker ECC raw public key",
        store_verify(store, eccSpki, eccSz));
    expect_untrusted("x509 store attacker RSA raw public key",
        store_verify(store, rsaSpki, rsaSz));

    wolfSSL_X509_free(ca);
    wolfSSL_X509_STORE_free(store);
    wolfSSL_CertManagerFree(cm);
    wolfSSL_CertManagerFree(empty);
    free(serverDer);
    free(clientDer);
    free(eccCertDer);
    wolfSSL_Cleanup();

    printf("%s (%d failure%s)\n",
        g_failures == 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED",
        g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}

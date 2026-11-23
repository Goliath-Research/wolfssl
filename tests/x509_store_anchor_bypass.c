/* Tests for the certificate-store trust-anchor decision.
 *
 * These checks are the expected behavior. They fail while a certificate whose
 * issuer and subject DER names differ can still be installed as a trusted CA
 * because the store compares display strings, and while a CA installed on
 * that path is accepted without a valid signature.
 *
 *   ./autogen.sh
 *   ./configure --enable-opensslextra --enable-certgen --enable-keygen \
 *       --enable-certext --disable-examples
 *   make -j
 *   gcc -Wall -Wextra -Werror -o x509_store_anchor_bypass \
 *       tests/x509_store_anchor_bypass.c -I. -Lsrc/.libs -lwolfssl -lm -lpthread
 *   LD_LIBRARY_PATH=src/.libs ./x509_store_anchor_bypass
 *
 * Exit status 1 means a leaf signed by the injected key was accepted.
 * Exit status 0 is the behavior after the trust-anchor decision is fixed.
 */

#include <wolfssl/options.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DER_CAP 4096
#define PEM_CAP 8192
#define NAME_CAP 256

enum {
    EXPECT_REJECT = 0,
    EXPECT_ACCEPT = 1
};

static int g_failures = 0;
static int g_harness = 0;

static void note_harness(const char* name, const char* why)
{
    fprintf(stderr, "HARNESS %s: %s\n", name, why);
    g_harness = 1;
}

static void note_result(const char* name, int accepted, int expectAccept,
    int verifyRet, int addRet)
{
    int bad = (accepted && !expectAccept) || (!accepted && expectAccept);

    if (bad) {
        fprintf(stderr,
            "FAIL %s: leaf %s (verify=%d add=%d), expected %s\n",
            name, accepted ? "accepted" : "rejected", verifyRet, addRet,
            expectAccept ? "accept" : "reject");
        g_failures++;
    }
    else {
        printf("PASS %s: leaf %s (verify=%d add=%d)\n",
            name, accepted ? "accepted" : "rejected", verifyRet, addRet);
    }
}

static int set_cn(CertName* name, const char* cn, char enc)
{
    size_t n = strlen(cn);

    if (n >= sizeof(name->commonName))
        return -1;
    memset(name->commonName, 0, sizeof(name->commonName));
    memcpy(name->commonName, cn, n);
    name->commonNameEnc = enc;
    return 0;
}

/* Issuer CN was generated as text ending in 'X'. Replace that byte with 0
 * inside the UTF8String so the display form truncates and the DER does not.
 * Call this on the unsigned body, before wc_SignCert. */
static int embed_nul_in_issuer(byte* der, int derSz, const char* issuerCn)
{
    byte pat[80];
    int n = (int)strlen(issuerCn);
    int patSz;
    int i;

    if (n < 2 || n > 60)
        return -1;
    pat[0] = 0x06;
    pat[1] = 0x03;
    pat[2] = 0x55;
    pat[3] = 0x04;
    pat[4] = 0x03;
    pat[5] = ASN_UTF8STRING;
    pat[6] = (byte)n;
    memcpy(pat + 7, issuerCn, (size_t)n);
    patSz = 7 + n;
    for (i = 0; i + patSz <= derSz; i++) {
        if (memcmp(der + i, pat, (size_t)patSz) == 0) {
            der[i + patSz - 1] = 0x00;
            return 0;
        }
    }
    return -1;
}

static int make_cert(WC_RNG* rng, ecc_key* subjectKey, ecc_key* signKey,
    const char* subjectCn, char subjectEnc, const char* issuerCn, char issuerEnc,
    int selfSigned, int isCa, int nulIssuer, int corruptSig,
    byte* der, int derCap, int* derSz)
{
    Cert* cert;
    int ret;
    int sz;

    cert = (Cert*)malloc(sizeof(Cert));
    if (cert == NULL)
        return -1;
    if (wc_InitCert(cert) != 0) {
        free(cert);
        return -1;
    }
    cert->selfSigned = selfSigned ? 1 : 0;
    cert->isCA = isCa ? 1 : 0;
    cert->sigType = CTC_SHA256wECDSA;
    if (set_cn(&cert->subject, subjectCn, subjectEnc) != 0 ||
            set_cn(&cert->issuer, issuerCn, issuerEnc) != 0) {
        free(cert);
        return -1;
    }
#ifdef WOLFSSL_CERT_EXT
    if (isCa) {
        if (wc_SetKeyUsage(cert, "keyCertSign,cRLSign") != 0) {
            free(cert);
            return -1;
        }
    }
#endif
    sz = wc_MakeCert(cert, der, (word32)derCap, NULL, subjectKey, rng);
    if (sz <= 0) {
        free(cert);
        return sz;
    }
    if (nulIssuer) {
        if (embed_nul_in_issuer(der, cert->bodySz, issuerCn) != 0) {
            free(cert);
            return -1;
        }
    }
    ret = wc_SignCert(cert->bodySz, cert->sigType, der, (word32)derCap,
        NULL, signKey, rng);
    free(cert);
    if (ret <= 0)
        return ret;
    if (corruptSig)
        der[ret - 1] = (byte)(der[ret - 1] ^ 0x01);
    *derSz = ret;
    return 0;
}

static int relation(const byte* der, int derSz, int* displayEqual, int* derEqual)
{
    DecodedCert* decoded;
    WOLFSSL_X509* x509;
    int ret;

    decoded = (DecodedCert*)malloc(sizeof(DecodedCert));
    if (decoded == NULL)
        return -1;
    wc_InitDecodedCert(decoded, der, (word32)derSz, NULL);
    ret = wc_ParseCert(decoded, CERT_TYPE, NO_VERIFY, NULL);
    if (ret != 0) {
        wc_FreeDecodedCert(decoded);
        free(decoded);
        return -1;
    }
    *derEqual = memcmp(decoded->issuerHash, decoded->subjectHash,
        KEYID_SIZE) == 0;
    wc_FreeDecodedCert(decoded);
    free(decoded);

    x509 = wolfSSL_X509_d2i(NULL, der, derSz);
    if (x509 == NULL)
        return -1;
    *displayEqual = wolfSSL_X509_NAME_cmp(
        wolfSSL_X509_get_issuer_name(x509),
        wolfSSL_X509_get_subject_name(x509)) == 0;
    wolfSSL_X509_free(x509);
    return 0;
}

static int verify_leaf(WOLFSSL_X509_STORE* store, WOLFSSL_X509* leaf,
    int* verifyRet)
{
    WOLFSSL_X509_STORE_CTX* ctx;
    int ret;

    ctx = wolfSSL_X509_STORE_CTX_new();
    if (ctx == NULL)
        return -1;
    if (wolfSSL_X509_STORE_CTX_init(ctx, store, leaf, NULL) != WOLFSSL_SUCCESS) {
        wolfSSL_X509_STORE_CTX_free(ctx);
        return -1;
    }
    ret = wolfSSL_X509_verify_cert(ctx);
    *verifyRet = ret;
    wolfSSL_X509_STORE_CTX_free(ctx);
    return ret == WOLFSSL_SUCCESS;
}

static int write_file(const char* path, const byte* buf, int sz)
{
    FILE* fp = fopen(path, "wb");
    size_t n;

    if (fp == NULL)
        return -1;
    n = fwrite(buf, 1, (size_t)sz, fp);
    if (fclose(fp) != 0 || n != (size_t)sz)
        return -1;
    return 0;
}

static int der_to_pem_file(const char* path, const byte* der, int derSz)
{
    byte pem[PEM_CAP];
    int pemSz = wc_DerToPem(der, (word32)derSz, pem, PEM_CAP, CERT_TYPE);

    if (pemSz <= 0)
        return -1;
    return write_file(path, pem, pemSz);
}

/* Install caDer through one of the store entry points and verify leafDer.
 * how: 0 = X509_STORE_add_cert, 1 = X509_STORE_load_locations (PEM file),
 * 2 = X509_load_cert_crl_file (DER file), 3 = add_cert after the store is
 * attached to an SSL_CTX (store->certs cleared). */
static void run_case(const char* name, WC_RNG* rng, ecc_key* caKey,
    ecc_key* leafKey, const char* subjectCn, char subjectEnc,
    const char* issuerCn, char issuerEnc, int selfSigned, int nulIssuer,
    int corruptSig, int how, int expectAccept)
{
    byte caDer[DER_CAP];
    byte leafDer[DER_CAP];
    int caSz = 0;
    int leafSz = 0;
    int displayEqual = 0;
    int derEqual = 0;
    int addRet = -1;
    int verifyRet = -1;
    int accepted = 0;
    int ret;
    WOLFSSL_X509* ca = NULL;
    WOLFSSL_X509* leaf = NULL;
    WOLFSSL_X509_STORE* store = NULL;
    WOLFSSL_CTX* sslCtx = NULL;
    char pemPath[256];
    char derPath[256];

    ret = make_cert(rng, caKey, caKey, subjectCn, subjectEnc, issuerCn,
        issuerEnc, selfSigned, 1, nulIssuer, corruptSig, caDer, DER_CAP, &caSz);
    if (ret != 0) {
        note_harness(name, "could not build CA certificate");
        return;
    }
    ret = make_cert(rng, leafKey, caKey, "LeafEndEntity", CTC_UTF8,
        subjectCn, subjectEnc, 0, 0, 0, 0, leafDer, DER_CAP, &leafSz);
    if (ret != 0) {
        note_harness(name, "could not build leaf certificate");
        return;
    }
    if (relation(caDer, caSz, &displayEqual, &derEqual) != 0) {
        note_harness(name, "could not decode CA certificate");
        return;
    }

    /* A collision case must actually collide in the display compare and must
     * not be a DER name match. A real self-signed case must be equal in both.
     * A distinct-name case must differ in both. Otherwise the assertion would
     * not be exercising the decision under test. */
    if (nulIssuer || (!selfSigned && subjectEnc != issuerEnc) ||
            (issuerCn != NULL && subjectCn != NULL &&
             strcmp(subjectCn, issuerCn) != 0 && !selfSigned &&
             subjectEnc == issuerEnc && !nulIssuer &&
             strlen(subjectCn) == strlen(issuerCn))) {
        if (!displayEqual || derEqual) {
            fprintf(stderr,
                "HARNESS %s: displayEqual=%d derEqual=%d, collision not formed\n",
                name, displayEqual, derEqual);
            g_harness = 1;
            return;
        }
    }
    else if (selfSigned) {
        if (!displayEqual || !derEqual) {
            fprintf(stderr,
                "HARNESS %s: displayEqual=%d derEqual=%d, self-signed name mismatch\n",
                name, displayEqual, derEqual);
            g_harness = 1;
            return;
        }
    }
    else if (!selfSigned && strcmp(subjectCn, issuerCn) != 0 &&
            strlen(subjectCn) != strlen(issuerCn)) {
        if (displayEqual || derEqual) {
            fprintf(stderr,
                "HARNESS %s: displayEqual=%d derEqual=%d, names unexpectedly matched\n",
                name, displayEqual, derEqual);
            g_harness = 1;
            return;
        }
    }

    leaf = wolfSSL_X509_d2i(NULL, leafDer, leafSz);
    if (leaf == NULL) {
        note_harness(name, "leaf d2i failed");
        return;
    }
    store = wolfSSL_X509_STORE_new();
    if (store == NULL) {
        note_harness(name, "store allocation failed");
        wolfSSL_X509_free(leaf);
        return;
    }

    if (how == 0) {
        ca = wolfSSL_X509_d2i(NULL, caDer, caSz);
        if (ca == NULL) {
            note_harness(name, "CA d2i failed");
            goto done;
        }
        addRet = wolfSSL_X509_STORE_add_cert(store, ca);
    }
    else if (how == 1) {
        snprintf(pemPath, sizeof(pemPath),
            "/tmp/wolfssl-anchor-%s.pem", name);
        if (der_to_pem_file(pemPath, caDer, caSz) != 0) {
            note_harness(name, "could not write PEM");
            goto done;
        }
        addRet = wolfSSL_X509_STORE_load_locations(store, pemPath, NULL);
    }
    else if (how == 2) {
        WOLFSSL_X509_LOOKUP_METHOD* method = wolfSSL_X509_LOOKUP_file();
        WOLFSSL_X509_LOOKUP* lookup;

        snprintf(derPath, sizeof(derPath),
            "/tmp/wolfssl-anchor-%s.der", name);
        if (write_file(derPath, caDer, caSz) != 0) {
            note_harness(name, "could not write DER");
            goto done;
        }
        lookup = wolfSSL_X509_STORE_add_lookup(store, method);
        if (lookup == NULL) {
            note_harness(name, "add_lookup failed");
            goto done;
        }
        addRet = wolfSSL_X509_load_cert_crl_file(lookup, derPath,
            WOLFSSL_FILETYPE_ASN1);
        /* This entry point returns a count. Normalize to success/failure. */
        addRet = (addRet > 0) ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
    }
    else if (how == 3) {
        sslCtx = wolfSSL_CTX_new(wolfSSLv23_client_method());
        if (sslCtx == NULL) {
            note_harness(name, "SSL_CTX_new failed");
            goto done;
        }
        wolfSSL_CTX_set_cert_store(sslCtx, store);
        ca = wolfSSL_X509_d2i(NULL, caDer, caSz);
        if (ca == NULL) {
            note_harness(name, "CA d2i failed");
            goto done;
        }
        addRet = wolfSSL_X509_STORE_add_cert(store, ca);
    }
    else {
        note_harness(name, "unknown install path");
        goto done;
    }

    ret = verify_leaf(store, leaf, &verifyRet);
    if (ret < 0) {
        note_harness(name, "verify setup failed");
        goto done;
    }
    accepted = ret;
    note_result(name, accepted, expectAccept, verifyRet, addRet);

done:
    wolfSSL_X509_free(ca);
    wolfSSL_X509_free(leaf);
    if (sslCtx != NULL) {
        /* The context owns the store after set_cert_store. */
        wolfSSL_CTX_free(sslCtx);
    }
    else {
        wolfSSL_X509_STORE_free(store);
    }
}

int main(void)
{
    WC_RNG rng;
    ecc_key caKey;
    ecc_key leafKey;
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "HARNESS wolfSSL_Init failed\n");
        return 2;
    }
    if (wc_InitRng(&rng) != 0) {
        fprintf(stderr, "HARNESS wc_InitRng failed\n");
        wolfSSL_Cleanup();
        return 2;
    }
    if (wc_ecc_init(&caKey) != 0 || wc_ecc_init(&leafKey) != 0 ||
            wc_ecc_make_key(&rng, 32, &caKey) != 0 ||
            wc_ecc_make_key(&rng, 32, &leafKey) != 0) {
        fprintf(stderr, "HARNESS ECC key generation failed\n");
        wc_ecc_free(&caKey);
        wc_ecc_free(&leafKey);
        wc_FreeRng(&rng);
        wolfSSL_Cleanup();
        return 2;
    }

    /* Controls. A real self-signed CA is a trust anchor. A certificate whose
     * display names differ is not. */
    run_case("true_self_signed_add_cert", &rng, &caKey, &leafKey,
        "RealRoot", CTC_UTF8, "RealRoot", CTC_UTF8,
        1, 0, 0, 0, EXPECT_ACCEPT);
    run_case("true_self_signed_load_locations", &rng, &caKey, &leafKey,
        "RealRoot", CTC_UTF8, "RealRoot", CTC_UTF8,
        1, 0, 0, 1, EXPECT_ACCEPT);
    run_case("true_self_signed_load_cert_crl_file", &rng, &caKey, &leafKey,
        "RealRoot", CTC_UTF8, "RealRoot", CTC_UTF8,
        1, 0, 0, 2, EXPECT_ACCEPT);
    run_case("distinct_names_add_cert", &rng, &caKey, &leafKey,
        "RealSubject", CTC_UTF8, "RealIssuer", CTC_UTF8,
        0, 0, 0, 0, EXPECT_REJECT);

    /* Display collision, signature valid under the key embedded in the CA
     * certificate, DER issuer and subject differ. */
    run_case("string_type_add_cert", &rng, &caKey, &leafKey,
        "TypeName", CTC_UTF8, "TypeName", CTC_PRINTABLE,
        0, 0, 0, 0, EXPECT_REJECT);
    run_case("string_type_load_locations", &rng, &caKey, &leafKey,
        "TypeName", CTC_UTF8, "TypeName", CTC_PRINTABLE,
        0, 0, 0, 1, EXPECT_REJECT);
    run_case("string_type_load_cert_crl_file", &rng, &caKey, &leafKey,
        "TypeName", CTC_UTF8, "TypeName", CTC_PRINTABLE,
        0, 0, 0, 2, EXPECT_REJECT);
    run_case("string_type_ctx_owned_store", &rng, &caKey, &leafKey,
        "TypeName", CTC_UTF8, "TypeName", CTC_PRINTABLE,
        0, 0, 0, 3, EXPECT_REJECT);
    run_case("letter_case_add_cert", &rng, &caKey, &leafKey,
        "CaseName", CTC_UTF8, "casename", CTC_UTF8,
        0, 0, 0, 0, EXPECT_REJECT);
    run_case("letter_case_load_locations", &rng, &caKey, &leafKey,
        "CaseName", CTC_UTF8, "casename", CTC_UTF8,
        0, 0, 0, 1, EXPECT_REJECT);
    run_case("embedded_nul_add_cert", &rng, &caKey, &leafKey,
        "NulAnchor", CTC_UTF8, "NulAnchorX", CTC_UTF8,
        0, 1, 0, 0, EXPECT_REJECT);
    run_case("embedded_nul_load_locations", &rng, &caKey, &leafKey,
        "NulAnchor", CTC_UTF8, "NulAnchorX", CTC_UTF8,
        0, 1, 0, 1, EXPECT_REJECT);

    /* Signature byte flipped after signing. A trust anchor must not be
     * installed when that signature does not verify under the certificate
     * key. */
    run_case("string_type_garbage_signature", &rng, &caKey, &leafKey,
        "TypeName", CTC_UTF8, "TypeName", CTC_PRINTABLE,
        0, 0, 1, 0, EXPECT_REJECT);
    run_case("true_self_signed_garbage_signature", &rng, &caKey, &leafKey,
        "RealRoot", CTC_UTF8, "RealRoot", CTC_UTF8,
        1, 0, 1, 0, EXPECT_REJECT);

    wc_ecc_free(&caKey);
    wc_ecc_free(&leafKey);
    wc_FreeRng(&rng);
    wolfSSL_Cleanup();

    if (g_harness) {
        fprintf(stderr, "harness error; results are incomplete\n");
        return 2;
    }
    if (g_failures) {
        fprintf(stderr, "%d security check(s) failed\n", g_failures);
        return 1;
    }
    printf("all security checks passed\n");
    return 0;
}

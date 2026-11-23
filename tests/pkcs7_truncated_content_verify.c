/* Tests for signature bypass via a truncated PKCS#7 ContentInfo length.
 *
 * These tests fail while wc_PKCS7_VerifySignedData() returns success for a
 * SignedData whose definite outer length ends fewer than six bytes after the
 * encapsulated content and which contains no signerInfos. They pass once that
 * input is rejected and a real signature still verifies.
 *
 * Build (from the repository root, after ./configure --enable-pkcs7
 * --enable-opensslextra --enable-opensslall && make):
 *
 *   gcc -Wall -Wextra -o tests/pkcs7_truncated_content_verify \
 *       tests/pkcs7_truncated_content_verify.c \
 *       -I. -Iwolfssl -Lsrc/.libs -lwolfssl -lm
 *   LD_LIBRARY_PATH=src/.libs ./tests/pkcs7_truncated_content_verify
 */

#include <wolfssl/options.h>

#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>

#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7)
    #include <wolfssl/openssl/pkcs7.h>
    #include <wolfssl/openssl/bio.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_SZ 48
#define DER_CAP    512

static int g_failures = 0;

static void fail(const char* name, const char* why)
{
    printf("FAIL %s: %s\n", name, why);
    g_failures++;
}

static void pass(const char* name)
{
    printf("PASS %s\n", name);
}

static int put_bytes(byte* dst, int cap, int* used, const byte* src, int n)
{
    if (*used > cap || n < 0 || n > cap - *used)
        return -1;
    if (n > 0)
        memcpy(dst + *used, src, (size_t)n);
    *used += n;
    return 0;
}

static int put_tag_len(byte* dst, int cap, int* used, byte tag, int len)
{
    byte hdr[2];

    if (len < 0 || len > 127)
        return -1;
    hdr[0] = tag;
    hdr[1] = (byte)len;
    return put_bytes(dst, cap, used, hdr, 2);
}

/* ContentInfo whose definite length ends `trailerSz` bytes after the
 * encapsulated content OCTET STRING. trailer bytes are inside that length.
 * No certificates and no signerInfos are present. Digest algorithms is a
 * non-empty SHA-256 AlgorithmIdentifier, so this is not an empty-digest
 * degenerate bundle. */
static int build_truncated_signed_data(byte* out, int cap, int* outSz,
    const byte* payload, int payloadSz, const byte* trailer, int trailerSz)
{
    static const byte oidSigned[] = {
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02
    };
    static const byte oidData[] = {
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01
    };
    static const byte sha256Null[] = {
        0x30, 0x0D,
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            0x05, 0x00
    };
    static const byte version[] = { 0x02, 0x01, 0x01 };
    byte body[DER_CAP];
    int bodySz = 0;
    int signedBody;
    int explicitBody;
    int contentInfoBody;

    if (payloadSz < 0 || payloadSz > 127 || trailerSz < 0 || trailerSz > 127)
        return -1;

    if (put_bytes(body, (int)sizeof(body), &bodySz, version,
            (int)sizeof(version)) != 0)
        return -1;
    if (put_tag_len(body, (int)sizeof(body), &bodySz,
            ASN_SET | ASN_CONSTRUCTED, (int)sizeof(sha256Null)) != 0)
        return -1;
    if (put_bytes(body, (int)sizeof(body), &bodySz, sha256Null,
            (int)sizeof(sha256Null)) != 0)
        return -1;

    /* encapContentInfo */
    {
        byte encap[DER_CAP];
        byte econtent[DER_CAP];
        int encapSz = 0;
        int econtentSz = 0;

        if (put_tag_len(econtent, (int)sizeof(econtent), &econtentSz,
                ASN_OCTET_STRING, payloadSz) != 0)
            return -1;
        if (put_bytes(econtent, (int)sizeof(econtent), &econtentSz,
                payload, payloadSz) != 0)
            return -1;

        if (put_bytes(encap, (int)sizeof(encap), &encapSz, oidData,
                (int)sizeof(oidData)) != 0)
            return -1;
        if (put_tag_len(encap, (int)sizeof(encap), &encapSz,
                (byte)(ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0),
                econtentSz) != 0)
            return -1;
        if (put_bytes(encap, (int)sizeof(encap), &encapSz, econtent,
                econtentSz) != 0)
            return -1;
        if (trailerSz > 0 && put_bytes(encap, (int)sizeof(encap), &encapSz,
                trailer, trailerSz) != 0)
            return -1;

        if (put_tag_len(body, (int)sizeof(body), &bodySz,
                ASN_SEQUENCE | ASN_CONSTRUCTED, encapSz) != 0)
            return -1;
        if (put_bytes(body, (int)sizeof(body), &bodySz, encap, encapSz) != 0)
            return -1;
    }

    signedBody = bodySz;
    explicitBody = 2 + signedBody;
    contentInfoBody = (int)sizeof(oidSigned) + 2 + explicitBody;
    if (contentInfoBody > 127 || signedBody > 127)
        return -1;

    *outSz = 0;
    if (put_tag_len(out, cap, outSz, ASN_SEQUENCE | ASN_CONSTRUCTED,
            contentInfoBody) != 0)
        return -1;
    if (put_bytes(out, cap, outSz, oidSigned, (int)sizeof(oidSigned)) != 0)
        return -1;
    if (put_tag_len(out, cap, outSz,
            (byte)(ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0),
            explicitBody) != 0)
        return -1;
    if (put_tag_len(out, cap, outSz, ASN_SEQUENCE | ASN_CONSTRUCTED,
            signedBody) != 0)
        return -1;
    if (put_bytes(out, cap, outSz, body, bodySz) != 0)
        return -1;
    return 0;
}

static int is_want_read(int err)
{
    return err == WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E);
}

static int verify_one_shot(const byte* msg, int msgSz, byte* contentOut,
    int* contentSz, int* verifyCertSet, int* signerSet)
{
    wc_PKCS7* pkcs7;
    int ret;

    *contentSz = -1;
    *verifyCertSet = 0;
    *signerSet = 0;

    pkcs7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (pkcs7 == NULL)
        return MEMORY_E;
    ret = wc_PKCS7_VerifySignedData(pkcs7, (byte*)msg, (word32)msgSz);
    if (ret == 0) {
        *contentSz = (int)pkcs7->contentSz;
        if (contentOut != NULL && pkcs7->content != NULL &&
                pkcs7->contentSz > 0 && pkcs7->contentSz <= PAYLOAD_SZ) {
            memcpy(contentOut, pkcs7->content, pkcs7->contentSz);
        }
        if (pkcs7->verifyCert != NULL)
            *verifyCertSet = 1;
        if (pkcs7->signerInfo != NULL)
            *signerSet = 1;
    }
    wc_PKCS7_Free(pkcs7);
    return ret;
}

static int verify_streamed(const byte* msg, int msgSz)
{
    wc_PKCS7* pkcs7;
    int ret = WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E);
    int i;

    pkcs7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (pkcs7 == NULL)
        return MEMORY_E;

    for (i = 0; i < msgSz; i++) {
        ret = wc_PKCS7_VerifySignedData(pkcs7, (byte*)msg + i, 1);
        if (ret == 0)
            break;
        if (!is_want_read(ret))
            break;
    }
    wc_PKCS7_Free(pkcs7);
    return ret;
}

static int verify_ex(const byte* msg, int msgSz, const byte* payload,
    int payloadSz)
{
    wc_PKCS7* pkcs7;
    byte digest[WC_SHA256_DIGEST_SIZE];
    int ret;

    pkcs7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (pkcs7 == NULL)
        return MEMORY_E;
    ret = wc_Sha256Hash(payload, (word32)payloadSz, digest);
    if (ret == 0) {
        ret = wc_PKCS7_VerifySignedData_ex(pkcs7, digest,
            (word32)sizeof(digest), (byte*)msg, (word32)msgSz, NULL, 0);
    }
    wc_PKCS7_Free(pkcs7);
    return ret;
}

/* The whole definite-length ContentInfo is in the buffer. Verification must
 * return a hard error. Success (0) is the bypass. WANT_READ is also a failure:
 * there is no further byte inside the declared length to read, and a caller
 * that retries would not be looking at a signature. */
static void expect_rejected(const char* name, int ret, int contentSz,
    const byte* content, const byte* payload, int payloadSz,
    int verifyCertSet, int signerSet)
{
    char why[320];
    int contentMatch;

    if (ret < 0 && !is_want_read(ret)) {
        pass(name);
        return;
    }

    contentMatch = (contentSz == payloadSz && content != NULL &&
        memcmp(content, payload, (size_t)payloadSz) == 0);
    if (ret == 0) {
        snprintf(why, sizeof(why),
            "returned success with no signer (verifyCert=%d signerInfo=%d "
            "contentSz=%d contentMatch=%d)",
            verifyCertSet, signerSet, contentSz, contentMatch);
    }
    else {
        snprintf(why, sizeof(why),
            "returned WANT_READ (%d) for a buffer that already holds the "
            "entire definite-length ContentInfo", ret);
    }
    fail(name, why);
}

static void test_truncated(const char* name, const byte* payload, int payloadSz,
    const byte* trailer, int trailerSz, const byte* extra, int extraSz)
{
    byte der[DER_CAP];
    byte msg[DER_CAP];
    byte got[PAYLOAD_SZ];
    int derSz = 0;
    int msgSz;
    int contentSz = -1;
    int verifyCertSet = 0;
    int signerSet = 0;
    int ret;
    char label[128];

    if (build_truncated_signed_data(der, (int)sizeof(der), &derSz,
            payload, payloadSz, trailer, trailerSz) != 0) {
        fail(name, "failed to build ContentInfo");
        return;
    }
    if (derSz + extraSz > (int)sizeof(msg)) {
        fail(name, "message does not fit");
        return;
    }
    memcpy(msg, der, (size_t)derSz);
    if (extraSz > 0)
        memcpy(msg + derSz, extra, (size_t)extraSz);
    msgSz = derSz + extraSz;

    memset(got, 0, sizeof(got));
    ret = verify_one_shot(msg, msgSz, got, &contentSz, &verifyCertSet,
        &signerSet);
    printf("  one-shot %s ret=%d contentSz=%d verifyCert=%d signerInfo=%d\n",
        name, ret, contentSz, verifyCertSet, signerSet);
    expect_rejected(name, ret, contentSz, got, payload, payloadSz,
        verifyCertSet, signerSet);

    snprintf(label, sizeof(label), "%s streamed", name);
    ret = verify_streamed(msg, msgSz);
    printf("  streamed %s ret=%d\n", name, ret);
    expect_rejected(label, ret, -1, NULL, payload, payloadSz, 0, 0);

    snprintf(label, sizeof(label), "%s VerifySignedData_ex", name);
    ret = verify_ex(msg, msgSz, payload, payloadSz);
    printf("  ex %s ret=%d\n", name, ret);
    expect_rejected(label, ret, -1, NULL, payload, payloadSz, 0, 0);
}

#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7) && !defined(NO_BIO)
static void test_openssl_wrappers(const byte* msg, int msgSz)
{
    const byte* p = msg;
    PKCS7* p7;
    BIO* bio;
    BIO* out;
    WOLFSSL_PKCS7* raw;
    int verifyRet;
    char* outPtr = NULL;
    int outSz;

    p7 = wolfSSL_d2i_PKCS7(NULL, &p, msgSz);
    if (p7 != NULL) {
        fail("wolfSSL_d2i_PKCS7 truncated",
            "accepted a SignedData with no signerInfos");
        wolfSSL_PKCS7_free(p7);
    }
    else {
        pass("wolfSSL_d2i_PKCS7 truncated");
    }

    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    if (bio == NULL) {
        fail("wolfSSL_d2i_PKCS7_bio truncated", "BIO_new failed");
    }
    else {
        if (wolfSSL_BIO_write(bio, msg, msgSz) != msgSz) {
            fail("wolfSSL_d2i_PKCS7_bio truncated", "BIO_write failed");
        }
        else {
            p7 = wolfSSL_d2i_PKCS7_bio(bio, NULL);
            if (p7 != NULL) {
                fail("wolfSSL_d2i_PKCS7_bio truncated",
                    "accepted a SignedData with no signerInfos");
                wolfSSL_PKCS7_free(p7);
            }
            else {
                pass("wolfSSL_d2i_PKCS7_bio truncated");
            }
        }
        wolfSSL_BIO_free(bio);
    }

    /* wolfSSL_PKCS7_verify checks verifyCert after the native verify call.
     * Feed the truncated blob directly so this still runs if d2i starts
     * rejecting it. */
    raw = (WOLFSSL_PKCS7*)wolfSSL_PKCS7_new();
    if (raw == NULL) {
        fail("wolfSSL_PKCS7_verify truncated", "PKCS7_new failed");
        return;
    }
    raw->data = (byte*)malloc((size_t)msgSz);
    if (raw->data == NULL) {
        wolfSSL_PKCS7_free((PKCS7*)raw);
        fail("wolfSSL_PKCS7_verify truncated", "malloc failed");
        return;
    }
    memcpy(raw->data, msg, (size_t)msgSz);
    raw->len = msgSz;
    out = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    verifyRet = wolfSSL_PKCS7_verify((PKCS7*)raw, NULL, NULL, NULL, out, 0);
    outSz = wolfSSL_BIO_get_mem_data(out, &outPtr);
    printf("  PKCS7_verify ret=%d outSz=%d\n", verifyRet, outSz);
    if (verifyRet == WOLFSSL_SUCCESS) {
        fail("wolfSSL_PKCS7_verify truncated",
            "reported success for content with no signer");
    }
    else if (outSz > 0) {
        fail("wolfSSL_PKCS7_verify truncated",
            "wrote content before rejecting");
    }
    else {
        pass("wolfSSL_PKCS7_verify truncated");
    }
    wolfSSL_BIO_free(out);
    wolfSSL_PKCS7_free((PKCS7*)raw);

    /* PKCS7_NOVERIFY skips chain building only. It must not accept this. */
    raw = (WOLFSSL_PKCS7*)wolfSSL_PKCS7_new();
    if (raw == NULL) {
        fail("wolfSSL_PKCS7_verify NOVERIFY truncated", "PKCS7_new failed");
        return;
    }
    raw->data = (byte*)malloc((size_t)msgSz);
    if (raw->data == NULL) {
        wolfSSL_PKCS7_free((PKCS7*)raw);
        fail("wolfSSL_PKCS7_verify NOVERIFY truncated", "malloc failed");
        return;
    }
    memcpy(raw->data, msg, (size_t)msgSz);
    raw->len = msgSz;
    out = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    verifyRet = wolfSSL_PKCS7_verify((PKCS7*)raw, NULL, NULL, NULL, out,
        PKCS7_NOVERIFY);
    outSz = wolfSSL_BIO_get_mem_data(out, &outPtr);
    if (verifyRet == WOLFSSL_SUCCESS || outSz > 0) {
        fail("wolfSSL_PKCS7_verify NOVERIFY truncated",
            "accepted or emitted content with no signer");
    }
    else {
        pass("wolfSSL_PKCS7_verify NOVERIFY truncated");
    }
    wolfSSL_BIO_free(out);
    wolfSSL_PKCS7_free((PKCS7*)raw);
}
#endif

static int load_file(const char* path, byte* buf, int cap, int* sz)
{
    FILE* fp;
    long n;

    fp = fopen(path, "rb");
    if (fp == NULL)
        return -1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    n = ftell(fp);
    if (n <= 0 || n > cap) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }
    if (fread(buf, 1, (size_t)n, fp) != (size_t)n) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *sz = (int)n;
    return 0;
}

/* A genuinely signed bundle must still verify. This keeps a fix that
 * rejects every input from satisfying the tests above. */
static void test_valid_signature_still_verifies(void)
{
    byte cert[4096];
    byte key[4096];
    byte out[8192];
    byte content[] = "legitimately-signed";
    int certSz = 0;
    int keySz = 0;
    int encSz;
    int ret;
    WC_RNG rng;
    wc_PKCS7* pkcs7;
    int rngInit = 0;

    if (load_file("./certs/client-cert.der", cert, (int)sizeof(cert),
            &certSz) != 0 ||
        load_file("./certs/client-key.der", key, (int)sizeof(key),
            &keySz) != 0) {
        fail("valid signature round trip", "could not read test cert or key");
        return;
    }

    if (wc_InitRng(&rng) != 0) {
        fail("valid signature round trip", "wc_InitRng failed");
        return;
    }
    rngInit = 1;

    pkcs7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (pkcs7 == NULL) {
        fail("valid signature round trip", "wc_PKCS7_New failed");
        wc_FreeRng(&rng);
        return;
    }
    ret = wc_PKCS7_InitWithCert(pkcs7, cert, (word32)certSz);
    if (ret == 0) {
        pkcs7->content = content;
        pkcs7->contentSz = (word32)(sizeof(content) - 1);
        pkcs7->privateKey = key;
        pkcs7->privateKeySz = (word32)keySz;
        pkcs7->encryptOID = RSAk;
        pkcs7->hashOID = SHA256h;
        pkcs7->rng = &rng;
        encSz = wc_PKCS7_EncodeSignedData(pkcs7, out, (word32)sizeof(out));
    }
    else {
        encSz = ret;
    }
    wc_PKCS7_Free(pkcs7);

    if (encSz <= 0) {
        printf("  encode ret=%d\n", encSz);
        fail("valid signature round trip", "wc_PKCS7_EncodeSignedData failed");
        wc_FreeRng(&rng);
        return;
    }

    pkcs7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (pkcs7 == NULL) {
        fail("valid signature round trip", "wc_PKCS7_New failed");
        wc_FreeRng(&rng);
        return;
    }
    ret = wc_PKCS7_VerifySignedData(pkcs7, out, (word32)encSz);
    printf("  valid one-shot ret=%d contentSz=%u\n", ret,
        ret == 0 ? pkcs7->contentSz : 0);
    if (ret != 0) {
        fail("valid signature round trip", "real signature was rejected");
    }
    else if (pkcs7->contentSz != (word32)(sizeof(content) - 1) ||
            pkcs7->content == NULL ||
            memcmp(pkcs7->content, content, pkcs7->contentSz) != 0) {
        fail("valid signature round trip", "verified content mismatch");
    }
    else if (pkcs7->verifyCert == NULL) {
        fail("valid signature round trip", "verifyCert was not set");
    }
    else {
        pass("valid signature round trip");
    }
    wc_PKCS7_Free(pkcs7);
    if (rngInit)
        wc_FreeRng(&rng);
    (void)rngInit;
}

/* Multipart constructed OCTET STRING. The same remaining-length check runs
 * after the parts are consumed. */
static int build_truncated_multipart(byte* out, int cap, int* outSz,
    const byte* partA, int partASz, const byte* partB, int partBSz)
{
    static const byte oidSigned[] = {
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02
    };
    static const byte oidData[] = {
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01
    };
    static const byte sha256Null[] = {
        0x30, 0x0D,
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            0x05, 0x00
    };
    static const byte version[] = { 0x02, 0x01, 0x01 };
    byte body[DER_CAP];
    byte encap[DER_CAP];
    byte constructed[DER_CAP];
    byte parts[DER_CAP];
    int bodySz = 0;
    int encapSz = 0;
    int constructedSz = 0;
    int partsSz = 0;
    int signedBody;
    int explicitBody;
    int contentInfoBody;

    if (put_tag_len(parts, (int)sizeof(parts), &partsSz, ASN_OCTET_STRING,
            partASz) != 0)
        return -1;
    if (put_bytes(parts, (int)sizeof(parts), &partsSz, partA, partASz) != 0)
        return -1;
    if (put_tag_len(parts, (int)sizeof(parts), &partsSz, ASN_OCTET_STRING,
            partBSz) != 0)
        return -1;
    if (put_bytes(parts, (int)sizeof(parts), &partsSz, partB, partBSz) != 0)
        return -1;
    if (put_tag_len(constructed, (int)sizeof(constructed), &constructedSz,
            ASN_OCTET_STRING | ASN_CONSTRUCTED, partsSz) != 0)
        return -1;
    if (put_bytes(constructed, (int)sizeof(constructed), &constructedSz,
            parts, partsSz) != 0)
        return -1;

    if (put_bytes(body, (int)sizeof(body), &bodySz, version,
            (int)sizeof(version)) != 0)
        return -1;
    if (put_tag_len(body, (int)sizeof(body), &bodySz,
            ASN_SET | ASN_CONSTRUCTED, (int)sizeof(sha256Null)) != 0)
        return -1;
    if (put_bytes(body, (int)sizeof(body), &bodySz, sha256Null,
            (int)sizeof(sha256Null)) != 0)
        return -1;

    if (put_bytes(encap, (int)sizeof(encap), &encapSz, oidData,
            (int)sizeof(oidData)) != 0)
        return -1;
    if (put_tag_len(encap, (int)sizeof(encap), &encapSz,
            (byte)(ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0),
            constructedSz) != 0)
        return -1;
    if (put_bytes(encap, (int)sizeof(encap), &encapSz, constructed,
            constructedSz) != 0)
        return -1;

    if (put_tag_len(body, (int)sizeof(body), &bodySz,
            ASN_SEQUENCE | ASN_CONSTRUCTED, encapSz) != 0)
        return -1;
    if (put_bytes(body, (int)sizeof(body), &bodySz, encap, encapSz) != 0)
        return -1;

    signedBody = bodySz;
    explicitBody = 2 + signedBody;
    contentInfoBody = (int)sizeof(oidSigned) + 2 + explicitBody;
    if (contentInfoBody > 127 || signedBody > 127)
        return -1;

    *outSz = 0;
    if (put_tag_len(out, cap, outSz, ASN_SEQUENCE | ASN_CONSTRUCTED,
            contentInfoBody) != 0)
        return -1;
    if (put_bytes(out, cap, outSz, oidSigned, (int)sizeof(oidSigned)) != 0)
        return -1;
    if (put_tag_len(out, cap, outSz,
            (byte)(ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0),
            explicitBody) != 0)
        return -1;
    if (put_tag_len(out, cap, outSz, ASN_SEQUENCE | ASN_CONSTRUCTED,
            signedBody) != 0)
        return -1;
    if (put_bytes(out, cap, outSz, body, bodySz) != 0)
        return -1;
    return 0;
}

static void test_multipart(const byte* payload, int payloadSz)
{
    byte der[DER_CAP];
    byte got[PAYLOAD_SZ];
    byte expect[PAYLOAD_SZ];
    int derSz = 0;
    int contentSz = -1;
    int verifyCertSet = 0;
    int signerSet = 0;
    int half;
    int ret;

    half = payloadSz / 2;
    if (build_truncated_multipart(der, (int)sizeof(der), &derSz,
            payload, half, payload + half, payloadSz - half) != 0) {
        fail("multipart truncated", "failed to build ContentInfo");
        return;
    }
    memcpy(expect, payload, (size_t)payloadSz);
    ret = verify_one_shot(der, derSz, got, &contentSz, &verifyCertSet,
        &signerSet);
    printf("  multipart ret=%d contentSz=%d\n", ret, contentSz);
    expect_rejected("multipart truncated", ret, contentSz, got, expect,
        payloadSz, verifyCertSet, signerSet);
}

int main(void)
{
    byte payload[PAYLOAD_SZ];
    byte extra[32];
    byte five[5];
    byte one[1];
    byte der[DER_CAP];
    int derSz = 0;
    int i;

    for (i = 0; i < PAYLOAD_SZ; i++)
        payload[i] = (byte)(0x41 + (i % 26));
    memset(extra, 0xBB, sizeof(extra));
    memset(five, 0xFF, sizeof(five));
    one[0] = 0xA0;

    printf("truncated content-length PKCS7 verify tests\n");

    test_truncated("trailer 0", payload, PAYLOAD_SZ, NULL, 0, NULL, 0);
    test_truncated("trailer 1 cert tag", payload, PAYLOAD_SZ, one, 1, NULL, 0);
    test_truncated("trailer 5 junk", payload, PAYLOAD_SZ, five, 5, NULL, 0);
    test_truncated("trailer 0 plus bytes past declared length",
        payload, PAYLOAD_SZ, NULL, 0, extra, (int)sizeof(extra));

    /* Incomplete signerInfos header: SET tag, long-form length, no body. */
    {
        byte partial[5] = { 0x31, 0x82, 0x01, 0x00, 0x30 };
        test_truncated("trailer partial signerInfos", payload, PAYLOAD_SZ,
            partial, 5, NULL, 0);
    }

    test_multipart(payload, PAYLOAD_SZ);

#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7) && !defined(NO_BIO)
    if (build_truncated_signed_data(der, (int)sizeof(der), &derSz,
            payload, PAYLOAD_SZ, NULL, 0) != 0) {
        fail("openssl wrappers", "failed to build ContentInfo");
    }
    else {
        test_openssl_wrappers(der, derSz);
    }
#else
    printf("SKIP openssl wrappers (OPENSSL_ALL/HAVE_PKCS7/BIO not enabled)\n");
#endif

    test_valid_signature_still_verifies();

    if (g_failures != 0) {
        printf("%d test(s) failed\n", g_failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}

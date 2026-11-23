/* Spec for the NuttX port entropy seed.
 *
 * Build this against RTOS/nuttx/wolfssl/user_settings.h (see the Makefile).
 * The port is safe when a fresh wc_InitRng / wc_InitRng_ex either refuses to
 * start, or does not reproduce the previous boot. These checks fail while
 * WOLFSSL_GENSEED_FORTEST feeds the public counter into the DRBG.
 *
 * Nothing here prints generated key material.
 *
 * Not executed here, same generator:
 * - PollAndReSeed runs only after WC_RESEED_INTERVAL blocks. The seed
 *   buffer it would pass to wc_GenerateSeed is checked below.
 * - wc_MakeRsaKey and RSA-PSS salts draw from wc_RNG_GenerateBlock.
 * - A TLS server flight needs a certificate. Its random and ECDHE key
 *   use wc_InitRng_ex and wc_ecc_make_key, which are checked below.
 * - X25519 and Ed25519 are not enabled by this user_settings.h.
 */

#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>

#define BLOCK_SZ 32
#define HELLO_CAP 8192

typedef struct HelloCap {
    byte buf[HELLO_CAP];
    int len;
    int overflow;
} HelloCap;

static int is_public_counter(const byte* p, word32 n)
{
    word32 i;

    for (i = 0; i < n; i++) {
        if (p[i] != (byte)i)
            return 0;
    }
    return 1;
}

/* 1 when this operation is reproducible across two fresh boots. */
static int rng_blocks_repeat(int use_ex)
{
    WC_RNG a;
    WC_RNG b;
    byte ba[BLOCK_SZ];
    byte bb[BLOCK_SZ];
    int ra;
    int rb;
    int ga;
    int gb;
    int same;

    XMEMSET(&a, 0, sizeof a);
    XMEMSET(&b, 0, sizeof b);
    if (use_ex) {
        ra = wc_InitRng_ex(&a, NULL, INVALID_DEVID);
        rb = wc_InitRng_ex(&b, NULL, INVALID_DEVID);
    }
    else {
        ra = wc_InitRng(&a);
        rb = wc_InitRng(&b);
    }
    if (ra != 0 || rb != 0) {
        if (ra == 0)
            wc_FreeRng(&a);
        if (rb == 0)
            wc_FreeRng(&b);
        return 0;
    }
    ga = wc_RNG_GenerateBlock(&a, ba, sizeof ba);
    gb = wc_RNG_GenerateBlock(&b, bb, sizeof bb);
    wc_FreeRng(&a);
    wc_FreeRng(&b);
    if (ga != 0 || gb != 0)
        return 0;
    same = (XMEMCMP(ba, bb, sizeof ba) == 0);
    wc_ForceZero(ba, sizeof ba);
    wc_ForceZero(bb, sizeof bb);
    return same;
}

static int public_nonce_repeats(void)
{
    WC_RNG a;
    WC_RNG b;
    byte nonce[8];
    byte ba[BLOCK_SZ];
    byte bb[BLOCK_SZ];
    int ra;
    int rb;
    int same;

    XMEMSET(nonce, 0, sizeof nonce);
    XMEMSET(&a, 0, sizeof a);
    XMEMSET(&b, 0, sizeof b);
    ra = wc_InitRngNonce(&a, nonce, (word32)sizeof nonce);
    rb = wc_InitRngNonce(&b, nonce, (word32)sizeof nonce);
    if (ra != 0 || rb != 0) {
        if (ra == 0)
            wc_FreeRng(&a);
        if (rb == 0)
            wc_FreeRng(&b);
        return 0;
    }
    ra = wc_RNG_GenerateBlock(&a, ba, sizeof ba);
    rb = wc_RNG_GenerateBlock(&b, bb, sizeof bb);
    wc_FreeRng(&a);
    wc_FreeRng(&b);
    if (ra != 0 || rb != 0)
        return 0;
    same = (XMEMCMP(ba, bb, sizeof ba) == 0);
    wc_ForceZero(ba, sizeof ba);
    wc_ForceZero(bb, sizeof bb);
    return same;
}

/* Seed buffer the DRBG init asks for when the nonce is empty, and the
 * buffer PollAndReSeed asks for. Both come from wc_GenerateSeed. */
static int seed_is_public_and_accepted(void)
{
    OS_Seed os;
    byte init_seed[WC_DRBG_MAX_SEED_SZ];
    byte reseed_seed[WC_DRBG_SEED_SZ + SEED_BLOCK_SZ];
    int ret;

    if (WC_DRBG_MAX_SEED_SZ < SEED_BLOCK_SZ)
        return 0;
    XMEMSET(&os, 0, sizeof os);
    ret = wc_GenerateSeed(&os, init_seed, (word32)sizeof init_seed);
    if (ret != 0)
        return 0;
    if (!is_public_counter(init_seed, (word32)sizeof init_seed))
        return 0;
    if (wc_RNG_TestSeed(init_seed, (word32)sizeof init_seed) != 0)
        return 0;

    ret = wc_GenerateSeed(&os, reseed_seed, (word32)sizeof reseed_seed);
    if (ret != 0)
        return 0;
    if (!is_public_counter(reseed_seed, (word32)sizeof reseed_seed))
        return 0;
    if (wc_RNG_TestSeed(reseed_seed, (word32)sizeof reseed_seed) != 0)
        return 0;
    return 1;
}

static int ecc_private_repeats(void)
{
    WC_RNG a;
    WC_RNG b;
    ecc_key* ka = NULL;
    ecc_key* kb = NULL;
    byte pa[MAX_ECC_BYTES];
    byte pb[MAX_ECC_BYTES];
    word32 la = (word32)sizeof pa;
    word32 lb = (word32)sizeof pb;
    int same = 0;
    int ret;

    XMEMSET(&a, 0, sizeof a);
    XMEMSET(&b, 0, sizeof b);
    if (wc_InitRng(&a) != 0 || wc_InitRng(&b) != 0)
        goto done;
    ka = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_ECC);
    kb = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_ECC);
    if (ka == NULL || kb == NULL)
        goto done;
    if (wc_ecc_init(ka) != 0 || wc_ecc_init(kb) != 0)
        goto done;
    if (wc_ecc_make_key(&a, 32, ka) != 0 || wc_ecc_make_key(&b, 32, kb) != 0)
        goto done;
    ret = wc_ecc_export_private_only(ka, pa, &la);
    if (ret != 0)
        goto done;
    ret = wc_ecc_export_private_only(kb, pb, &lb);
    if (ret != 0)
        goto done;
    same = (la == lb && la > 0 && XMEMCMP(pa, pb, la) == 0);

done:
    wc_ForceZero(pa, sizeof pa);
    wc_ForceZero(pb, sizeof pb);
    if (ka != NULL) {
        wc_ecc_free(ka);
        XFREE(ka, NULL, DYNAMIC_TYPE_ECC);
    }
    if (kb != NULL) {
        wc_ecc_free(kb);
        XFREE(kb, NULL, DYNAMIC_TYPE_ECC);
    }
    wc_FreeRng(&a);
    wc_FreeRng(&b);
    return same;
}

static int ecc_signature_repeats(void)
{
    WC_RNG rng;
    WC_RNG sign_a;
    WC_RNG sign_b;
    ecc_key* key = NULL;
    byte hash[32];
    byte sig_a[ECC_MAX_SIG_SIZE];
    byte sig_b[ECC_MAX_SIG_SIZE];
    word32 sig_a_sz = (word32)sizeof sig_a;
    word32 sig_b_sz = (word32)sizeof sig_b;
    int same = 0;

    XMEMSET(hash, 0x11, sizeof hash);
    XMEMSET(&rng, 0, sizeof rng);
    XMEMSET(&sign_a, 0, sizeof sign_a);
    XMEMSET(&sign_b, 0, sizeof sign_b);
    if (wc_InitRng(&rng) != 0)
        goto done;
    key = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_ECC);
    if (key == NULL)
        goto done;
    if (wc_ecc_init(key) != 0)
        goto done;
    if (wc_ecc_make_key(&rng, 32, key) != 0)
        goto done;
    /* Signing nonces come from a fresh boot of the same generator. */
    if (wc_InitRng(&sign_a) != 0 || wc_InitRng(&sign_b) != 0)
        goto done;
    if (wc_ecc_sign_hash(hash, (word32)sizeof hash, sig_a, &sig_a_sz,
                         &sign_a, key) != 0)
        goto done;
    if (wc_ecc_sign_hash(hash, (word32)sizeof hash, sig_b, &sig_b_sz,
                         &sign_b, key) != 0)
        goto done;
    same = (sig_a_sz == sig_b_sz && sig_a_sz > 0 &&
            XMEMCMP(sig_a, sig_b, sig_a_sz) == 0);

done:
    wc_ForceZero(sig_a, sizeof sig_a);
    wc_ForceZero(sig_b, sizeof sig_b);
    if (key != NULL) {
        wc_ecc_free(key);
        XFREE(key, NULL, DYNAMIC_TYPE_ECC);
    }
    wc_FreeRng(&rng);
    wc_FreeRng(&sign_a);
    wc_FreeRng(&sign_b);
    return same;
}

static int dh_private_repeats(void)
{
    WC_RNG a;
    WC_RNG b;
    DhKey* ka = NULL;
    DhKey* kb = NULL;
    byte priv_a[256];
    byte priv_b[256];
    byte pub_a[512];
    byte pub_b[512];
    word32 priv_a_sz = (word32)sizeof priv_a;
    word32 priv_b_sz = (word32)sizeof priv_b;
    word32 pub_a_sz = (word32)sizeof pub_a;
    word32 pub_b_sz = (word32)sizeof pub_b;
    int same = 0;

    XMEMSET(&a, 0, sizeof a);
    XMEMSET(&b, 0, sizeof b);
    if (wc_InitRng(&a) != 0 || wc_InitRng(&b) != 0)
        goto done;
    ka = (DhKey*)XMALLOC(sizeof(DhKey), NULL, DYNAMIC_TYPE_DH);
    kb = (DhKey*)XMALLOC(sizeof(DhKey), NULL, DYNAMIC_TYPE_DH);
    if (ka == NULL || kb == NULL)
        goto done;
    if (wc_InitDhKey(ka) != 0 || wc_InitDhKey(kb) != 0)
        goto done;
    if (wc_DhSetNamedKey(ka, WC_FFDHE_2048) != 0 ||
        wc_DhSetNamedKey(kb, WC_FFDHE_2048) != 0)
        goto done;
    if (wc_DhGenerateKeyPair(ka, &a, priv_a, &priv_a_sz, pub_a, &pub_a_sz) != 0)
        goto done;
    if (wc_DhGenerateKeyPair(kb, &b, priv_b, &priv_b_sz, pub_b, &pub_b_sz) != 0)
        goto done;
    same = (priv_a_sz == priv_b_sz && priv_a_sz > 0 &&
            XMEMCMP(priv_a, priv_b, priv_a_sz) == 0);

done:
    wc_ForceZero(priv_a, sizeof priv_a);
    wc_ForceZero(priv_b, sizeof priv_b);
    wc_ForceZero(pub_a, sizeof pub_a);
    wc_ForceZero(pub_b, sizeof pub_b);
    if (ka != NULL) {
        wc_FreeDhKey(ka);
        XFREE(ka, NULL, DYNAMIC_TYPE_DH);
    }
    if (kb != NULL) {
        wc_FreeDhKey(kb);
        XFREE(kb, NULL, DYNAMIC_TYPE_DH);
    }
    wc_FreeRng(&a);
    wc_FreeRng(&b);
    return same;
}

static int send_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    HelloCap* cap = (HelloCap*)ctx;

    (void)ssl;
    if (sz < 0)
        return WOLFSSL_CBIO_ERR_GENERAL;
    if (cap->len > HELLO_CAP - sz) {
        cap->overflow = 1;
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    XMEMCPY(cap->buf + cap->len, buf, (size_t)sz);
    cap->len += sz;
    return sz;
}

static int recv_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)buf;
    (void)sz;
    (void)ctx;
    return WOLFSSL_CBIO_ERR_WANT_READ;
}

static int capture_client_hello(HelloCap* cap)
{
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int ret;
    int err;
    int ok = 0;

    XMEMSET(cap, 0, sizeof *cap);
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL)
        return 0;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_CTX_SetIORecv(ctx, recv_cb);
    wolfSSL_CTX_SetIOSend(ctx, send_cb);
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
        goto done;
    wolfSSL_SetIOReadCtx(ssl, cap);
    wolfSSL_SetIOWriteCtx(ssl, cap);
    ret = wolfSSL_connect(ssl);
    if (ret == WOLFSSL_SUCCESS) {
        /* A finished handshake without a peer is not this test. */
        goto done;
    }
    err = wolfSSL_get_error(ssl, ret);
    if (err != WOLFSSL_ERROR_WANT_READ && err != WANT_READ)
        goto done;
    ok = (cap->overflow == 0 && cap->len > 0);

done:
    if (ssl != NULL)
        wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return ok;
}

static int tls13_client_hello_repeats(int* wrote)
{
    HelloCap a;
    HelloCap b;
    int same;

    *wrote = 0;
    if (!capture_client_hello(&a)) {
        wc_ForceZero(a.buf, sizeof a.buf);
        return 0;
    }
    if (!capture_client_hello(&b)) {
        wc_ForceZero(a.buf, sizeof a.buf);
        wc_ForceZero(b.buf, sizeof b.buf);
        return 0;
    }
    *wrote = a.len;
    same = (a.len == b.len && a.len > 0 && XMEMCMP(a.buf, b.buf, (size_t)a.len) == 0);
    wc_ForceZero(a.buf, sizeof a.buf);
    wc_ForceZero(b.buf, sizeof b.buf);
    return same;
}

static int report(const char* name, int predictable)
{
    printf("%s %s\n", predictable ? "FAIL" : "ok  ", name);
    return predictable;
}

int main(void)
{
    int failures = 0;
    int hello_len = 0;

    if (wolfCrypt_Init() != 0) {
        fprintf(stderr, "wolfCrypt_Init failed\n");
        return 2;
    }
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed\n");
        wolfCrypt_Cleanup();
        return 2;
    }

    failures += report("wc_GenerateSeed public counter accepted by wc_RNG_TestSeed",
                       seed_is_public_and_accepted());
    failures += report("wc_InitRng block repeats", rng_blocks_repeat(0));
    failures += report("wc_InitRng_ex block repeats", rng_blocks_repeat(1));
    failures += report("wc_InitRngNonce with a public nonce repeats",
                       public_nonce_repeats());
    failures += report("wc_ecc_make_key private repeats", ecc_private_repeats());
    failures += report("wc_ecc_sign_hash nonce repeats", ecc_signature_repeats());
    failures += report("wc_DhGenerateKeyPair private repeats", dh_private_repeats());
    failures += report("TLS 1.3 ClientHello repeats",
                       tls13_client_hello_repeats(&hello_len));
    if (hello_len > 0)
        printf("info TLS 1.3 ClientHello length %d\n", hello_len);

    wolfSSL_Cleanup();
    wolfCrypt_Cleanup();

    printf("%d predictable operation%s\n", failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}

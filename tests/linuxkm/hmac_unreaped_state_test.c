/* Unreaped HMAC / SHA-3 working states in the Linux kernel crypto glue.
 *
 * The wolfSSL module registers shash algorithms. AF_ALG reaches them through
 * the kernel's shash-backed ahash wrapper. This file compiles the glue and
 * drives the same calls algif_hash makes for:
 *   setkey, sendmsg(MSG_MORE) -> init+update, accept -> export+import,
 *   close of the child -> hash_sock_destruct, which does not call final.
 *
 * Kernel sources this stand-in follows (read, not assumed):
 *   Linux v6.12 crypto/algif_hash.c hash_sendmsg, hash_accept,
 *     hash_sock_destruct, hash_accept_parent_nokey
 *   Linux v6.12.113 crypto/algif_hash.c hash_accept_parent_nokey (memset)
 *   Linux v5.15 crypto/algif_hash.c hash_sendmsg, hash_accept,
 *     hash_sock_destruct, hash_accept_parent_nokey (no memset of the req)
 *   Linux v6.12 crypto/ahash.c crypto_ahash_init/export/import and
 *     crypto_init_ahash_using_shash
 *   Linux v6.12 crypto/shash.c crypto_shash_setkey/init/export/import
 *   Linux v6.12 include/crypto/hash.h crypto_shash_init
 *   Linux v6.12 include/crypto/internal/hash.h crypto_shash_alg_needs_key
 *
 * Expectation until the glue is fixed: re-init, re-import, and the
 * accept/close loop leave working nodes on the transform past
 * WC_LINUXKM_HMAC_EXPORT_LIST_MAX. exit_tfm is the only full reaper, and the
 * parent socket stays open across the loop, so exit_tfm has not run.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <linux/list.h>

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;

static size_t g_glue_allocs;

static void *track_malloc(size_t n)
{
    void *p = malloc(n);

    if (p != NULL)
        g_glue_allocs++;
    return p;
}

static void track_free(void *p)
{
    if (p == NULL)
        return;
    g_glue_allocs--;
    free(p);
}

#define malloc(n) track_malloc(n)
#define free(p) track_free(p)

#define LINUXKM_LKCAPI_REGISTER
#define LINUXKM_LKCAPI_REGISTER_HMAC_ALL
#define LINUXKM_LKCAPI_REGISTER_SHA3
#ifndef WOLFSSL_LINUXKM_LKCAPI_PRIORITY
    #define WOLFSSL_LINUXKM_LKCAPI_PRIORITY 100000
#endif
#define WOLFKM_DRIVER_SUFFIX_BASE "-wolfcrypt"
#define THIS_MODULE ((void *)0)

/* v6.12 is above the glue's 5.6 floor and is a version this module patches. */
#define KERNEL_VERSION(a, b, c) (((a) << 16) | ((b) << 8) | (c))
#define LINUX_VERSION_CODE KERNEL_VERSION(6, 12, 0)

struct crypto_tfm {
    void *ctx;
};

struct crypto_shash {
    unsigned int descsize;
    struct crypto_tfm base;
    struct shash_alg *alg;
    uint32_t flags;
};

struct shash_desc {
    struct crypto_shash *tfm;
    unsigned char __ctx[] __attribute__((aligned(8)));
};

#define HASH_MAX_DESCSIZE (sizeof(struct shash_desc) + 360)

struct crypto_alg {
    const char *cra_name;
    const char *cra_driver_name;
    int cra_priority;
    unsigned int cra_blocksize;
    unsigned int cra_ctxsize;
    void *cra_module;
    unsigned int cra_flags;
};

struct shash_alg {
    int (*init)(struct shash_desc *);
    int (*update)(struct shash_desc *, const u8 *, unsigned int);
    int (*final)(struct shash_desc *, u8 *);
    int (*finup)(struct shash_desc *, const u8 *, unsigned int, u8 *);
    int (*digest)(struct shash_desc *, const u8 *, unsigned int, u8 *);
    int (*export)(struct shash_desc *, void *);
    int (*import)(struct shash_desc *, const void *);
    int (*setkey)(struct crypto_shash *, const u8 *, unsigned int);
    int (*init_tfm)(struct crypto_shash *);
    void (*exit_tfm)(struct crypto_shash *);
    int (*clone_tfm)(struct crypto_shash *, struct crypto_shash *);
    unsigned int descsize;
    unsigned int digestsize;
    unsigned int statesize;
    struct crypto_alg base;
};

#define CRYPTO_TFM_NEED_KEY 0x00000001
#define CRYPTO_ALG_OPTIONAL_KEY 0x00000002

/* nr_cpu_ids * 2 is the glue's export-list cap. Pin the cpu count so the
 * bound under test is the formula in lkcapi_sha_glue.c, not a hard-coded
 * substitute.
 */
#define nr_cpu_ids 2

static inline void *crypto_tfm_ctx(struct crypto_tfm *tfm)
{
    return tfm->ctx;
}

static inline void *crypto_shash_ctx(struct crypto_shash *tfm)
{
    return crypto_tfm_ctx(&tfm->base);
}

static inline void *shash_desc_ctx(struct shash_desc *desc)
{
    return desc->__ctx;
}

static inline struct shash_alg *crypto_shash_alg(struct crypto_shash *tfm)
{
    return tfm->alg;
}

static inline uint32_t crypto_shash_get_flags(struct crypto_shash *tfm)
{
    return tfm->flags;
}

static inline void crypto_shash_set_flags(struct crypto_shash *tfm, uint32_t f)
{
    tfm->flags |= f;
}

static inline void crypto_shash_clear_flags(struct crypto_shash *tfm, uint32_t f)
{
    tfm->flags &= ~f;
}

static inline unsigned long long get_random_u64(void)
{
    return 0x5743484d41435f31ULL;
}

#define IS_ERR(ptr) ((unsigned long)(void *)(ptr) >= (unsigned long)-4095)
#define PTR_ERR(ptr) ((long)(void *)(ptr))
#define ERR_PTR(err) ((void *)(long)(err))

#define pr_err(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

typedef int wc_test_ret_t;
#define WC_TEST_RET_DEC_EC(x) (x)

wc_test_ret_t hmac_sha_test(void) { return 0; }
wc_test_ret_t hmac_sha224_test(void) { return 0; }
wc_test_ret_t hmac_sha256_test(void) { return 0; }
wc_test_ret_t hmac_sha384_test(void) { return 0; }
wc_test_ret_t hmac_sha512_test(void) { return 0; }
wc_test_ret_t hmac_sha3_test(void) { return 0; }
wc_test_ret_t sha3_test(void) { return 0; }
void wc_test_render_error_message(const char *msg, wc_test_ret_t es)
{
    (void)msg;
    (void)es;
}

int crypto_shash_setkey(struct crypto_shash *tfm, const u8 *key,
                        unsigned int keylen);
int crypto_shash_init(struct shash_desc *desc);
int crypto_shash_update(struct shash_desc *desc, const u8 *data,
                        unsigned int len);
int crypto_shash_final(struct shash_desc *desc, u8 *out);
int crypto_shash_export(struct shash_desc *desc, void *out);
int crypto_shash_import(struct shash_desc *desc, const void *in);
unsigned int crypto_shash_digestsize(struct crypto_shash *tfm);
unsigned int crypto_shash_descsize(struct crypto_shash *tfm);
unsigned int crypto_shash_statesize(struct crypto_shash *tfm);
struct crypto_shash *crypto_alloc_shash(const char *alg, uint32_t type,
                                       uint32_t mask);
void crypto_free_shash(struct crypto_shash *tfm);

static int check_shash_driver_masking(struct crypto_shash *tfm,
                                     const char *alg_name,
                                     const char *expected_driver_name)
{
    (void)tfm;
    (void)alg_name;
    (void)expected_driver_name;
    return 0;
}

#include "../../linuxkm/lkcapi_sha_glue.c"

#undef malloc
#undef free

/* ---- kernel shash / ahash stand-ins (v6.12 crypto/shash.c, ahash.c) ---- */

static int alg_needs_key(struct shash_alg *alg)
{
    /* crypto_shash_alg_needs_key: setkey is not the default no-setkey, and
     * CRYPTO_ALG_OPTIONAL_KEY is clear. HMAC registers setkey. SHA-3 does not,
     * so shash_prepare_alg would install shash_no_setkey and needs_key is false.
     */
    return alg->setkey != NULL &&
           (alg->base.cra_flags & CRYPTO_ALG_OPTIONAL_KEY) == 0;
}

int crypto_shash_setkey(struct crypto_shash *tfm, const u8 *key,
                        unsigned int keylen)
{
    struct shash_alg *alg = crypto_shash_alg(tfm);
    int err;

    if (alg->setkey == NULL)
        return -ENOSYS;
    err = alg->setkey(tfm, key, keylen);
    if (err != 0) {
        if (alg_needs_key(alg))
            crypto_shash_set_flags(tfm, CRYPTO_TFM_NEED_KEY);
        return err;
    }
    crypto_shash_clear_flags(tfm, CRYPTO_TFM_NEED_KEY);
    return 0;
}

int crypto_shash_init(struct shash_desc *desc)
{
    struct crypto_shash *tfm = desc->tfm;

    if (crypto_shash_get_flags(tfm) & CRYPTO_TFM_NEED_KEY)
        return -ENOKEY;
    return crypto_shash_alg(tfm)->init(desc);
}

int crypto_shash_update(struct shash_desc *desc, const u8 *data,
                        unsigned int len)
{
    return crypto_shash_alg(desc->tfm)->update(desc, data, len);
}

int crypto_shash_final(struct shash_desc *desc, u8 *out)
{
    return crypto_shash_alg(desc->tfm)->final(desc, out);
}

int crypto_shash_export(struct shash_desc *desc, void *out)
{
    struct shash_alg *alg = crypto_shash_alg(desc->tfm);

    if (alg->export != NULL)
        return alg->export(desc, out);
    memcpy(out, shash_desc_ctx(desc), desc->tfm->descsize);
    return 0;
}

int crypto_shash_import(struct shash_desc *desc, const void *in)
{
    struct shash_alg *alg = crypto_shash_alg(desc->tfm);

    if (crypto_shash_get_flags(desc->tfm) & CRYPTO_TFM_NEED_KEY)
        return -ENOKEY;
    if (alg->import != NULL)
        return alg->import(desc, in);
    memcpy(shash_desc_ctx(desc), in, desc->tfm->descsize);
    return 0;
}

unsigned int crypto_shash_digestsize(struct crypto_shash *tfm)
{
    return tfm->alg->digestsize;
}

unsigned int crypto_shash_descsize(struct crypto_shash *tfm)
{
    return tfm->descsize;
}

unsigned int crypto_shash_statesize(struct crypto_shash *tfm)
{
    return tfm->alg->statesize;
}

struct crypto_shash *crypto_alloc_shash(const char *alg, uint32_t type,
                                       uint32_t mask)
{
    (void)alg;
    (void)type;
    (void)mask;
    return ERR_PTR(-ENOENT);
}

void crypto_free_shash(struct crypto_shash *tfm)
{
    (void)tfm;
}

/* ahash using_shash path. wolfssl registers shash_alg; crypto_init_ahash_using_shash
 * sets using_shash and points the ahash at that shash. export uses the existing
 * request desc; import/init call prepare_shash_desc, which only stores the tfm.
 */
struct ahash_req {
    struct crypto_shash *shash;
    struct shash_desc *desc;
};

static struct shash_desc *prepare_shash_desc(struct ahash_req *req)
{
    req->desc->tfm = req->shash;
    return req->desc;
}

static int crypto_ahash_init(struct ahash_req *req)
{
    return crypto_shash_init(prepare_shash_desc(req));
}

static int crypto_ahash_update(struct ahash_req *req, const u8 *data,
                              unsigned int len)
{
    return crypto_shash_update(req->desc, data, len);
}

static int crypto_ahash_export(struct ahash_req *req, void *out)
{
    return crypto_shash_export(req->desc, out);
}

static int crypto_ahash_import(struct ahash_req *req, const void *in)
{
    return crypto_shash_import(prepare_shash_desc(req), in);
}

/* ---- AF_ALG hash socket stand-in ---- */

struct hash_op {
    bool more;
    struct crypto_shash *tfm;
    struct ahash_req req;
    unsigned char descmem[];
};

enum desc_fill {
    DESC_ZERO = 0,     /* Linux v6.12.113 and v7.0 hash_accept_parent_nokey */
    DESC_POISON = 1    /* v5.10 .. v6.15 tags: sock_kmalloc, fields set, tail untouched */
};

static struct crypto_shash *alloc_tfm(struct shash_alg *alg)
{
    struct crypto_shash *tfm = calloc(1, sizeof(*tfm));
    void *ctx;

    if (tfm == NULL)
        return NULL;
    ctx = calloc(1, alg->base.cra_ctxsize);
    if (ctx == NULL) {
        free(tfm);
        return NULL;
    }
    tfm->base.ctx = ctx;
    tfm->alg = alg;
    /* crypto_shash_init_tfm stores descsize before init_tfm. */
    tfm->descsize = alg->descsize;
    if (alg_needs_key(alg))
        crypto_shash_set_flags(tfm, CRYPTO_TFM_NEED_KEY);
    if (alg->init_tfm != NULL && alg->init_tfm(tfm) != 0) {
        free(ctx);
        free(tfm);
        return NULL;
    }
    return tfm;
}

static void free_tfm(struct crypto_shash *tfm)
{
    if (tfm == NULL)
        return;
    if (tfm->alg->exit_tfm != NULL)
        tfm->alg->exit_tfm(tfm);
    free(tfm->base.ctx);
    free(tfm);
}

static struct hash_op *new_hash_op(struct crypto_shash *tfm, enum desc_fill fill)
{
    size_t bytes = sizeof(struct hash_op) + sizeof(struct shash_desc) +
                   tfm->descsize;
    struct hash_op *op = malloc(bytes);

    if (op == NULL)
        return NULL;
    memset(op, fill == DESC_ZERO ? 0 : 0xa5, bytes);
    op->more = false;
    op->tfm = tfm;
    op->req.shash = tfm;
    op->req.desc = (struct shash_desc *)op->descmem;
    /* prepare_shash_desc / ahash_request_set_tfm store the tfm. The ctx tail
     * stays zero or 0xa5, matching the two kernel accept-parent variants.
     */
    op->req.desc->tfm = tfm;
    return op;
}

static void destroy_hash_op(struct hash_op *op)
{
    /* hash_sock_destruct frees the ctx and does not call crypto_ahash_final. */
    free(op);
}

/* Non-empty sendmsg with MSG_MORE. v6.12 hash_sendmsg (need_init + update,
 * no finup) and v5.15 hash_sendmsg (init when !more, update, skip final
 * because MSG_MORE is set). Both leave ctx->more true.
 */
static int hash_sendmsg_more(struct hash_op *op, const u8 *data, unsigned int len)
{
    int err = 0;

    if (!op->more) {
        err = crypto_ahash_init(&op->req);
        if (err != 0) {
            op->more = false;
            return err;
        }
    }
    err = crypto_ahash_update(&op->req, data, len);
    if (err != 0) {
        op->more = false;
        return err;
    }
    op->more = true;
    return 0;
}

/* hash_accept: export only when more is set, then import into the child.
 * v6.12 drops the parent lock between export and import; this single-threaded
 * stand-in still runs export to completion before import, which is the order
 * those calls observe.
 */
static int hash_accept_child(struct hash_op *parent, enum desc_fill fill,
                            struct hash_op **child_out)
{
    bool more = parent->more;
    void *state = NULL;
    struct hash_op *child;
    int err = 0;

    *child_out = NULL;
    if (more) {
        state = malloc(parent->tfm->alg->statesize);
        if (state == NULL)
            return -ENOMEM;
        err = crypto_ahash_export(&parent->req, state);
        if (err != 0) {
            free(state);
            return err;
        }
    }

    child = new_hash_op(parent->tfm, fill);
    if (child == NULL) {
        free(state);
        return -ENOMEM;
    }
    child->more = more;
    if (!more) {
        free(state);
        *child_out = child;
        return 0;
    }

    err = crypto_ahash_import(&child->req, state);
    free(state);
    if (err != 0) {
        destroy_hash_op(child);
        return err;
    }
    *child_out = child;
    return 0;
}

enum alg_kind { ALG_HMAC = 1, ALG_SHA3 = 2 };

static unsigned count_nodes(struct list_head *head, size_t offset)
{
    unsigned count = 0;
    struct list_head *pos;

    for (pos = head->next; pos != head; pos = pos->next)
        count++;
    (void)offset;
    return count;
}

static unsigned desc_nodes(struct crypto_shash *tfm, enum alg_kind kind)
{
    if (kind == ALG_HMAC) {
        struct km_sha_hmac_pstate *p = crypto_shash_ctx(tfm);
        return count_nodes(&p->desc_list, 0);
    } else {
        struct km_Sha3TfmCtx *t = crypto_shash_ctx(tfm);
        return count_nodes(&t->desc_list, 0);
    }
}

static unsigned export_nodes(struct crypto_shash *tfm, enum alg_kind kind)
{
    if (kind != ALG_HMAC)
        return 0;
    return ((struct km_sha_hmac_pstate *)crypto_shash_ctx(tfm))->export_list_len;
}

static int g_failed;
static int g_checks;

static void expect_le(const char *name, unsigned got, unsigned limit,
                     const char *what)
{
    g_checks++;
    if (got > limit) {
        fprintf(stderr, "FAIL %s: %s=%u exceeds limit %u (glue allocs=%zu)\n",
                name, what, got, limit, g_glue_allocs);
        g_failed++;
    } else {
        fprintf(stderr, "PASS %s: %s=%u limit=%u\n", name, what, got, limit);
    }
}

static void expect_eq(const char *name, unsigned got, unsigned want,
                     const char *what)
{
    g_checks++;
    if (got != want) {
        fprintf(stderr, "FAIL %s: %s=%u want %u (glue allocs=%zu)\n",
                name, what, got, want, g_glue_allocs);
        g_failed++;
    } else {
        fprintf(stderr, "PASS %s: %s=%u\n", name, what, got);
    }
}

static int harness_fail(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "HARNESS ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    g_failed++;
    g_checks++;
    return -1;
}

static const u8 k_msg[16] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};
static const u8 k_key[32] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44
};

static int prepare_keyed(struct crypto_shash *tfm, enum alg_kind kind)
{
    int err;

    if (kind != ALG_HMAC)
        return 0;
    if ((crypto_shash_get_flags(tfm) & CRYPTO_TFM_NEED_KEY) == 0)
        return harness_fail("HMAC tfm was not born needing a key");
    err = crypto_shash_setkey(tfm, k_key, sizeof(k_key));
    if (err != 0)
        return harness_fail("setkey failed: %d", err);
    if (crypto_shash_get_flags(tfm) & CRYPTO_TFM_NEED_KEY)
        return harness_fail("setkey left CRYPTO_TFM_NEED_KEY set");
    return 0;
}

static int test_reinit(struct shash_alg *alg, enum alg_kind kind)
{
    struct crypto_shash *tfm = alloc_tfm(alg);
    struct hash_op *op;
    char name[96];
    int err;

    snprintf(name, sizeof(name), "%s reinit", alg->base.cra_name);
    if (tfm == NULL)
        return harness_fail("%s: alloc tfm", name);
    if (prepare_keyed(tfm, kind) != 0) {
        free_tfm(tfm);
        return -1;
    }
    op = new_hash_op(tfm, DESC_POISON);
    if (op == NULL) {
        free_tfm(tfm);
        return harness_fail("%s: alloc op", name);
    }
    err = crypto_ahash_init(&op->req);
    if (err == 0)
        err = crypto_ahash_init(&op->req);
    if (err != 0) {
        destroy_hash_op(op);
        free_tfm(tfm);
        return harness_fail("%s: init returned %d", name, err);
    }
    /* Same descriptor, second init. The previous working node must be freed,
     * not left on the transform until exit_tfm.
     */
    expect_eq(name, desc_nodes(tfm, kind), 1, "desc_nodes");
    destroy_hash_op(op);
    free_tfm(tfm);
    return 0;
}

static int test_reimport(struct shash_alg *alg, enum alg_kind kind)
{
    struct crypto_shash *tfm = alloc_tfm(alg);
    struct hash_op *parent;
    struct hash_op *child;
    void *blob;
    char name[96];
    unsigned before;
    int err;

    snprintf(name, sizeof(name), "%s reimport", alg->base.cra_name);
    if (tfm == NULL)
        return harness_fail("%s: alloc tfm", name);
    if (prepare_keyed(tfm, kind) != 0) {
        free_tfm(tfm);
        return -1;
    }
    parent = new_hash_op(tfm, DESC_ZERO);
    if (parent == NULL) {
        free_tfm(tfm);
        return harness_fail("%s: alloc parent", name);
    }
    err = hash_sendmsg_more(parent, k_msg, sizeof(k_msg));
    if (err != 0) {
        destroy_hash_op(parent);
        free_tfm(tfm);
        return harness_fail("%s: sendmsg %d", name, err);
    }
    blob = malloc(alg->statesize);
    child = new_hash_op(tfm, DESC_POISON);
    if (blob == NULL || child == NULL) {
        free(blob);
        destroy_hash_op(child);
        destroy_hash_op(parent);
        free_tfm(tfm);
        return harness_fail("%s: alloc", name);
    }
    child->req.shash = tfm;
    err = crypto_ahash_export(&parent->req, blob);
    if (err == 0)
        err = crypto_ahash_import(&child->req, blob);
    if (err != 0) {
        free(blob);
        destroy_hash_op(child);
        destroy_hash_op(parent);
        free_tfm(tfm);
        return harness_fail("%s: first import %d", name, err);
    }
    before = desc_nodes(tfm, kind);
    err = crypto_ahash_import(&child->req, blob);
    free(blob);
    if (err != 0) {
        destroy_hash_op(child);
        destroy_hash_op(parent);
        free_tfm(tfm);
        return harness_fail("%s: second import %d", name, err);
    }
    expect_eq(name, desc_nodes(tfm, kind), before, "desc_nodes");
    destroy_hash_op(child);
    destroy_hash_op(parent);
    free_tfm(tfm);
    return 0;
}

static int test_accept_close(struct shash_alg *alg, enum alg_kind kind,
                            enum desc_fill fill)
{
    struct crypto_shash *tfm = alloc_tfm(alg);
    struct hash_op *parent;
    char name[128];
    unsigned rounds;
    unsigned limit;
    unsigned i;
    int err;
    const char *fill_name = (fill == DESC_ZERO) ? "zeroed-child" : "poison-child";

    snprintf(name, sizeof(name), "%s accept/close %s", alg->base.cra_name,
             fill_name);
    rounds = (WC_LINUXKM_HMAC_EXPORT_LIST_MAX * 4);
    if (rounds < 8)
        rounds = 8;
    /* One live parent descriptor, plus the same ceiling the export snapshot
     * list already enforces. Closed children are not live descriptors.
     */
    limit = WC_LINUXKM_HMAC_EXPORT_LIST_MAX + 1;

    if (tfm == NULL)
        return harness_fail("%s: alloc tfm", name);
    if (prepare_keyed(tfm, kind) != 0) {
        free_tfm(tfm);
        return -1;
    }
    parent = new_hash_op(tfm, DESC_ZERO);
    if (parent == NULL) {
        free_tfm(tfm);
        return harness_fail("%s: alloc parent", name);
    }
    err = hash_sendmsg_more(parent, k_msg, sizeof(k_msg));
    if (err != 0) {
        destroy_hash_op(parent);
        free_tfm(tfm);
        return harness_fail("%s: sendmsg %d", name, err);
    }

    for (i = 0; i < rounds; i++) {
        struct hash_op *child = NULL;

        err = hash_accept_child(parent, fill, &child);
        if (err != 0 || child == NULL) {
            destroy_hash_op(parent);
            free_tfm(tfm);
            return harness_fail("%s: accept %u returned %d", name, i, err);
        }
        /* Parent socket stays open. Child close does not call final. */
        destroy_hash_op(child);
    }

    if (kind == ALG_HMAC &&
        export_nodes(tfm, kind) > WC_LINUXKM_HMAC_EXPORT_LIST_MAX) {
        destroy_hash_op(parent);
        free_tfm(tfm);
        return harness_fail("%s: export list uncapped (%u)", name,
                            export_nodes(tfm, kind));
    }
    expect_le(name, desc_nodes(tfm, kind), limit, "desc_nodes");
    /* Nodes that were unlinked but not freed still show up here. Export
     * snapshots are allowed up to the existing cap; working states are not
     * allowed to grow with the number of closed children.
     */
    expect_le(name, (unsigned)g_glue_allocs,
              limit + export_nodes(tfm, kind), "glue_allocs");

    destroy_hash_op(parent);
    free_tfm(tfm);
    return 0;
}

static int test_accept_without_more(struct shash_alg *alg, enum alg_kind kind)
{
    struct crypto_shash *tfm = alloc_tfm(alg);
    struct hash_op *parent;
    char name[96];
    unsigned i;
    int err;

    snprintf(name, sizeof(name), "%s accept without MSG_MORE", alg->base.cra_name);
    if (tfm == NULL)
        return harness_fail("%s: alloc tfm", name);
    if (prepare_keyed(tfm, kind) != 0) {
        free_tfm(tfm);
        return -1;
    }
    parent = new_hash_op(tfm, DESC_POISON);
    if (parent == NULL) {
        free_tfm(tfm);
        return harness_fail("%s: alloc parent", name);
    }
    /* more is false: hash_accept must not export or import. */
    for (i = 0; i < 8; i++) {
        struct hash_op *child = NULL;

        err = hash_accept_child(parent, DESC_POISON, &child);
        if (err != 0) {
            destroy_hash_op(parent);
            free_tfm(tfm);
            return harness_fail("%s: accept %d", name, err);
        }
        destroy_hash_op(child);
    }
    expect_eq(name, desc_nodes(tfm, kind), 0, "desc_nodes");
    destroy_hash_op(parent);
    free_tfm(tfm);
    return 0;
}

static int test_final_frees(struct shash_alg *alg, enum alg_kind kind)
{
    struct crypto_shash *tfm = alloc_tfm(alg);
    struct hash_op *op;
    u8 out[64];
    char name[96];
    int err;

    snprintf(name, sizeof(name), "%s final frees", alg->base.cra_name);
    if (tfm == NULL)
        return harness_fail("%s: alloc tfm", name);
    if (prepare_keyed(tfm, kind) != 0) {
        free_tfm(tfm);
        return -1;
    }
    op = new_hash_op(tfm, DESC_ZERO);
    if (op == NULL) {
        free_tfm(tfm);
        return harness_fail("%s: alloc", name);
    }
    err = hash_sendmsg_more(op, k_msg, sizeof(k_msg));
    if (err == 0)
        err = crypto_shash_final(op->req.desc, out);
    if (err != 0) {
        destroy_hash_op(op);
        free_tfm(tfm);
        return harness_fail("%s: final %d", name, err);
    }
    expect_eq(name, desc_nodes(tfm, kind), 0, "desc_nodes");
    destroy_hash_op(op);
    free_tfm(tfm);
    return 0;
}

struct alg_entry {
    struct shash_alg *alg;
    enum alg_kind kind;
};

int main(void)
{
    struct alg_entry algs[] = {
        { &sha1_hmac_alg, ALG_HMAC },
        { &sha2_224_hmac_alg, ALG_HMAC },
        { &sha2_256_hmac_alg, ALG_HMAC },
        { &sha2_384_hmac_alg, ALG_HMAC },
        { &sha2_512_hmac_alg, ALG_HMAC },
        { &sha3_224_hmac_alg, ALG_HMAC },
        { &sha3_256_hmac_alg, ALG_HMAC },
        { &sha3_384_hmac_alg, ALG_HMAC },
        { &sha3_512_hmac_alg, ALG_HMAC },
        { &sha3_224_alg, ALG_SHA3 },
        { &sha3_256_alg, ALG_SHA3 },
        { &sha3_384_alg, ALG_SHA3 },
        { &sha3_512_alg, ALG_SHA3 },
    };
    size_t i;

    fprintf(stderr, "WC_LINUXKM_HMAC_EXPORT_LIST_MAX=%u (nr_cpu_ids=%d)\n",
            WC_LINUXKM_HMAC_EXPORT_LIST_MAX, nr_cpu_ids);

    for (i = 0; i < sizeof(algs) / sizeof(algs[0]); i++) {
        test_final_frees(algs[i].alg, algs[i].kind);
        test_accept_without_more(algs[i].alg, algs[i].kind);
        test_reinit(algs[i].alg, algs[i].kind);
        test_reimport(algs[i].alg, algs[i].kind);
        test_accept_close(algs[i].alg, algs[i].kind, DESC_ZERO);
        test_accept_close(algs[i].alg, algs[i].kind, DESC_POISON);
        if (g_glue_allocs != 0) {
            fprintf(stderr, "HARNESS %s: glue allocs left=%zu after exit_tfm\n",
                    algs[i].alg->base.cra_name, g_glue_allocs);
            g_failed++;
            g_glue_allocs = 0;
        }
    }

    fprintf(stderr, "%d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}

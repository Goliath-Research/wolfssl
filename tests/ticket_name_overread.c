/* Regression tests for the example session-ticket callback.
 *
 * examples/server/server.c and examples/echoserver/echoserver.c install
 * myTicketEncCb() from wolfssl/test.h when HAVE_TEST_SESSION_TICKET is set.
 * On a name mismatch that callback prints the client-supplied 16-byte key
 * name with "%s". These tests send a ClientHello through wolfSSL_accept()
 * and require the log line to contain only those 16 bytes.
 *
 * These checks fail while that printf walks past the field. A bounded print
 * (precision 16, or a 17-byte terminated copy) makes them pass.
 *
 * DTLS (src/dtls.c TlsTicketIsValid) calls the same callback and is not
 * driven here.
 *
 *   ./configure --enable-session-ticket --enable-opensslall \
 *       --disable-examples --disable-crypttests --disable-shared \
 *       CFLAGS="-DWOLFSSL_NO_DEF_TICKET_ENC_CB -DKEEP_PEER_CERT -g -O1"
 *   make -j src/libwolfssl.la
 *   gcc -DWOLFSSL_NO_DEF_TICKET_ENC_CB -DKEEP_PEER_CERT -g -O1 -I. \
 *       tests/ticket_name_overread.c src/.libs/libwolfssl.a \
 *       -o /tmp/ticket_name_overread -lm -pthread
 *   /tmp/ticket_name_overread
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>

#define USE_CERT_BUFFERS_2048
#include <wolfssl/certs_test.h>
#include <wolfssl/test.h>

#ifndef HAVE_TEST_SESSION_TICKET
#error "Build with session tickets and -DWOLFSSL_NO_DEF_TICKET_ENC_CB"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>

/* Place each block at the end of a readable page, filled with 0xff, with the
 * following page unmapped. A "%s" walk past the requested size faults. */
struct GuardHdr {
    void* base;
    size_t total;
    size_t n;
};

static void* guard_malloc(size_t n)
{
    size_t bytes = n == 0 ? 1 : n;
    size_t total;
    void* base;
    unsigned char* user;
    struct GuardHdr hdr;

    total = 4096 + bytes + 4096;
    total = (total + 4095u) & ~(size_t)4095u;
    base = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0);
    if (base == MAP_FAILED)
        return NULL;
    if (mprotect((unsigned char*)base + total - 4096, 4096, PROT_NONE) != 0) {
        munmap(base, total);
        return NULL;
    }
    user = (unsigned char*)base + total - 4096 - bytes;
    memset(user, 0xff, bytes);
    hdr.base = base;
    hdr.total = total;
    hdr.n = bytes;
    memcpy(user - sizeof(hdr), &hdr, sizeof(hdr));
    return user;
}

static void guard_free(void* p)
{
    struct GuardHdr hdr;

    if (p == NULL)
        return;
    memcpy(&hdr, (unsigned char*)p - sizeof(hdr), sizeof(hdr));
    munmap(hdr.base, hdr.total);
}

static void* guard_realloc(void* p, size_t n)
{
    struct GuardHdr hdr;
    void* np;
    size_t copy;

    if (p == NULL)
        return guard_malloc(n);
    memcpy(&hdr, (unsigned char*)p - sizeof(hdr), sizeof(hdr));
    np = guard_malloc(n);
    if (np == NULL)
        return NULL;
    copy = hdr.n < n ? hdr.n : n;
    memcpy(np, p, copy);
    guard_free(p);
    return np;
}

#define NAME_BYTE 0x41
#define IV_BYTE   0x42
#define MARK_BYTE 0x51
#define FILL_BYTE 0x61

static const char kLogPrefix[] = "client presented unknown ticket key name ";

typedef struct {
    const unsigned char* data;
    int len;
    int off;
} IoBuf;

static int io_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    IoBuf* io = (IoBuf*)ctx;
    int n;

    (void)ssl;
    if (io->off >= io->len)
        return WOLFSSL_CBIO_ERR_WANT_READ;
    n = io->len - io->off;
    if (n > sz)
        n = sz;
    memcpy(buf, io->data + io->off, (size_t)n);
    io->off += n;
    return n;
}

static int io_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)buf;
    (void)ctx;
    return sz;
}

static int append_bytes(unsigned char* dst, int cap, int* off,
                        const unsigned char* src, int n)
{
    if (*off < 0 || n < 0 || *off > cap - n)
        return -1;
    if (n > 0)
        memcpy(dst + *off, src, (size_t)n);
    *off += n;
    return 0;
}

static int append_u8(unsigned char* dst, int cap, int* off, unsigned char v)
{
    return append_bytes(dst, cap, off, &v, 1);
}

static int append_u16(unsigned char* dst, int cap, int* off, unsigned int v)
{
    unsigned char b[2];

    b[0] = (unsigned char)((v >> 8) & 0xff);
    b[1] = (unsigned char)(v & 0xff);
    return append_bytes(dst, cap, off, b, 2);
}

static int append_u24(unsigned char* dst, int cap, int* off, unsigned int v)
{
    unsigned char b[3];

    b[0] = (unsigned char)((v >> 16) & 0xff);
    b[1] = (unsigned char)((v >> 8) & 0xff);
    b[2] = (unsigned char)(v & 0xff);
    return append_bytes(dst, cap, off, b, 3);
}

/* External ticket: name || iv || enc_len || ciphertext || mac.
 * enc_len is the ciphertext length the server checks before the callback.
 * Returns the ticket length, or -1. */
static int build_ticket(unsigned char* ticket, int cap, unsigned int in_len)
{
    unsigned int ticket_len;
    int off = 0;

    ticket_len = in_len + (unsigned int)WOLFSSL_TICKET_FIXED_SZ;
    if (in_len > 0xffffu || ticket_len > (unsigned int)SESSION_TICKET_LEN ||
            ticket_len > (unsigned int)cap ||
            in_len < (unsigned int)WOLFSSL_INTERNAL_TICKET_LEN ||
            in_len > (unsigned int)WOLFSSL_TICKET_ENC_SZ)
        return -1;

    memset(ticket, FILL_BYTE, ticket_len);
    memset(ticket, NAME_BYTE, WOLFSSL_TICKET_NAME_SZ);
    memset(ticket + WOLFSSL_TICKET_NAME_SZ, IV_BYTE, WOLFSSL_TICKET_IV_SZ);
    ticket[WOLFSSL_TICKET_NAME_SZ + WOLFSSL_TICKET_IV_SZ] =
        (unsigned char)((in_len >> 8) & 0xff);
    ticket[WOLFSSL_TICKET_NAME_SZ + WOLFSSL_TICKET_IV_SZ + 1] =
        (unsigned char)(in_len & 0xff);
    /* Marker sits in the ciphertext, after the length field. */
    if (ticket_len > (unsigned int)(WOLFSSL_TICKET_NAME_SZ +
                                    WOLFSSL_TICKET_IV_SZ + 2))
        ticket[WOLFSSL_TICKET_NAME_SZ + WOLFSSL_TICKET_IV_SZ + 2] = MARK_BYTE;
    (void)off;
    return (int)ticket_len;
}

/* TLS 1.2 ClientHello record whose session_ticket extension is the last
 * extension and ends at the end of the record body. */
static int build_tls12_ticket_record(unsigned char* out, int cap,
                                     const unsigned char* ticket, int ticket_len)
{
    unsigned char body[4096];
    int body_off = 0;
    int hello_off;
    int ext_off;
    int rec_off = 0;
    unsigned char random[32];
    unsigned int hello_len;
    unsigned int ext_len;

    memset(random, 0x11, sizeof(random));

    if (append_u8(body, (int)sizeof(body), &body_off, 1) != 0)
        return -1;
    hello_off = body_off;
    if (append_u24(body, (int)sizeof(body), &body_off, 0) != 0)
        return -1;
    if (append_u16(body, (int)sizeof(body), &body_off, 0x0303) != 0)
        return -1;
    if (append_bytes(body, (int)sizeof(body), &body_off, random, 32) != 0)
        return -1;
    if (append_u8(body, (int)sizeof(body), &body_off, 0) != 0)
        return -1;
    if (append_u16(body, (int)sizeof(body), &body_off, 2) != 0)
        return -1;
    /* TLS_RSA_WITH_AES_128_CBC_SHA. The zero is before the ticket. */
    if (append_u16(body, (int)sizeof(body), &body_off, 0x002f) != 0)
        return -1;
    if (append_u8(body, (int)sizeof(body), &body_off, 1) != 0)
        return -1;
    if (append_u8(body, (int)sizeof(body), &body_off, 0) != 0)
        return -1;

    ext_off = body_off;
    if (append_u16(body, (int)sizeof(body), &body_off, 0) != 0)
        return -1;
    /* session_ticket = 35 */
    if (append_u16(body, (int)sizeof(body), &body_off, 35) != 0)
        return -1;
    if (append_u16(body, (int)sizeof(body), &body_off,
                   (unsigned int)ticket_len) != 0)
        return -1;
    if (append_bytes(body, (int)sizeof(body), &body_off, ticket, ticket_len) != 0)
        return -1;

    ext_len = (unsigned int)(body_off - (ext_off + 2));
    body[ext_off] = (unsigned char)((ext_len >> 8) & 0xff);
    body[ext_off + 1] = (unsigned char)(ext_len & 0xff);

    hello_len = (unsigned int)(body_off - (hello_off + 3));
    body[hello_off] = (unsigned char)((hello_len >> 16) & 0xff);
    body[hello_off + 1] = (unsigned char)((hello_len >> 8) & 0xff);
    body[hello_off + 2] = (unsigned char)(hello_len & 0xff);

    if (append_u8(out, cap, &rec_off, 22) != 0)
        return -1;
    if (append_u16(out, cap, &rec_off, 0x0303) != 0)
        return -1;
    if (append_u16(out, cap, &rec_off, (unsigned int)body_off) != 0)
        return -1;
    if (append_bytes(out, cap, &rec_off, body, body_off) != 0)
        return -1;
    return rec_off;
}

/* TLS 1.3 ClientHello. The pre_shared_key identity is the ticket and is the
 * last extension. */
static int build_tls13_psk_record(unsigned char* out, int cap,
                                  const unsigned char* ticket, int ticket_len)
{
    unsigned char body[4096];
    unsigned char random[32];
    unsigned char legacy_id[32];
    int body_off = 0;
    int hello_off;
    int ext_off;
    int ids_off;
    int binders_off;
    int rec_off = 0;
    unsigned int hello_len;
    unsigned int ext_len;
    unsigned int ids_len;
    unsigned int binders_len;
    unsigned char binder[32];

    memset(random, 0x11, sizeof(random));
    memset(legacy_id, 0x22, sizeof(legacy_id));
    memset(binder, 0x33, sizeof(binder));

    if (append_u8(body, (int)sizeof(body), &body_off, 1) != 0)
        return -1;
    hello_off = body_off;
    if (append_u24(body, (int)sizeof(body), &body_off, 0) != 0)
        return -1;
    if (append_u16(body, (int)sizeof(body), &body_off, 0x0303) != 0)
        return -1;
    if (append_bytes(body, (int)sizeof(body), &body_off, random, 32) != 0)
        return -1;
    if (append_u8(body, (int)sizeof(body), &body_off, 32) != 0)
        return -1;
    if (append_bytes(body, (int)sizeof(body), &body_off, legacy_id, 32) != 0)
        return -1;
    if (append_u16(body, (int)sizeof(body), &body_off, 2) != 0)
        return -1;
    /* TLS_AES_128_GCM_SHA256 */
    if (append_u16(body, (int)sizeof(body), &body_off, 0x1301) != 0)
        return -1;
    if (append_u8(body, (int)sizeof(body), &body_off, 1) != 0)
        return -1;
    if (append_u8(body, (int)sizeof(body), &body_off, 0) != 0)
        return -1;

    ext_off = body_off;
    if (append_u16(body, (int)sizeof(body), &body_off, 0) != 0)
        return -1;

    /* supported_versions = 43, one version: TLS 1.3 */
    if (append_u16(body, (int)sizeof(body), &body_off, 43) != 0)
        return -1;
    if (append_u16(body, (int)sizeof(body), &body_off, 3) != 0)
        return -1;
    if (append_u8(body, (int)sizeof(body), &body_off, 2) != 0)
        return -1;
    if (append_u16(body, (int)sizeof(body), &body_off, 0x0304) != 0)
        return -1;

    /* signature_algorithms = 13, rsa_pkcs1_sha256 (0x0401). */
    if (append_u16(body, (int)sizeof(body), &body_off, 13) != 0)
        return -1;
    if (append_u16(body, (int)sizeof(body), &body_off, 4) != 0)
        return -1;
    if (append_u16(body, (int)sizeof(body), &body_off, 2) != 0)
        return -1;
    if (append_u16(body, (int)sizeof(body), &body_off, 0x0401) != 0)
        return -1;

    /* pre_shared_key = 41, must be last. No key_share: the ticket callback
     * runs while the identity is decoded, before key share is required. */
    if (append_u16(body, (int)sizeof(body), &body_off, 41) != 0)
        return -1;
    ids_off = body_off; /* extension length filled after the body is known */
    if (append_u16(body, (int)sizeof(body), &body_off, 0) != 0)
        return -1;
    if (append_u16(body, (int)sizeof(body), &body_off, 0) != 0) /* identities len */
        return -1;
    if (append_u16(body, (int)sizeof(body), &body_off,
                   (unsigned int)ticket_len) != 0)
        return -1;
    if (append_bytes(body, (int)sizeof(body), &body_off, ticket, ticket_len) != 0)
        return -1;
    if (append_u16(body, (int)sizeof(body), &body_off, 0) != 0) /* age high */
        return -1;
    if (append_u16(body, (int)sizeof(body), &body_off, 0) != 0) /* age low */
        return -1;
    ids_len = (unsigned int)(body_off - (ids_off + 4));
    body[ids_off + 2] = (unsigned char)((ids_len >> 8) & 0xff);
    body[ids_off + 3] = (unsigned char)(ids_len & 0xff);

    binders_off = body_off;
    if (append_u16(body, (int)sizeof(body), &body_off, 0) != 0)
        return -1;
    if (append_u8(body, (int)sizeof(body), &body_off, 32) != 0)
        return -1;
    if (append_bytes(body, (int)sizeof(body), &body_off, binder, 32) != 0)
        return -1;
    binders_len = (unsigned int)(body_off - (binders_off + 2));
    body[binders_off] = (unsigned char)((binders_len >> 8) & 0xff);
    body[binders_off + 1] = (unsigned char)(binders_len & 0xff);

    {
        unsigned int psk_len = (unsigned int)(body_off - (ids_off + 2));
        body[ids_off] = (unsigned char)((psk_len >> 8) & 0xff);
        body[ids_off + 1] = (unsigned char)(psk_len & 0xff);
    }

    ext_len = (unsigned int)(body_off - (ext_off + 2));
    body[ext_off] = (unsigned char)((ext_len >> 8) & 0xff);
    body[ext_off + 1] = (unsigned char)(ext_len & 0xff);

    hello_len = (unsigned int)(body_off - (hello_off + 3));
    body[hello_off] = (unsigned char)((hello_len >> 16) & 0xff);
    body[hello_off + 1] = (unsigned char)((hello_len >> 8) & 0xff);
    body[hello_off + 2] = (unsigned char)(hello_len & 0xff);

    if (append_u8(out, cap, &rec_off, 22) != 0)
        return -1;
    if (append_u16(out, cap, &rec_off, 0x0301) != 0)
        return -1;
    if (append_u16(out, cap, &rec_off, (unsigned int)body_off) != 0)
        return -1;
    if (append_bytes(out, cap, &rec_off, body, body_off) != 0)
        return -1;
    return rec_off;
}

/* Returns 0 when the logged key name is exactly the 16 name bytes.
 * Returns 1 when the callback printed past those bytes.
 * Returns 2 when the callback log line was not produced.
 * Returns 3 on a local setup failure. */
static int drive_server(const unsigned char* record, int record_len,
                        char* captured, int captured_cap)
{
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_METHOD* method;
    MyTicketCtx ticket_ctx;
    IoBuf io;
    int rc = 3;
    int ticket_ready = 0;
    int saved_out = -1;
    int nread;
    int total = 0;
    FILE* logf = NULL;

    captured[0] = '\0';
    if (wolfSSL_SetAllocators(guard_malloc, guard_free, guard_realloc) != 0)
        return 3;
    logf = tmpfile();
    if (logf == NULL)
        return 3;
    saved_out = dup(STDOUT_FILENO);
    if (saved_out < 0)
        goto done;
    if (dup2(fileno(logf), STDOUT_FILENO) < 0)
        goto done;
    setvbuf(stdout, NULL, _IONBF, 0);

    method = wolfSSLv23_server_method();
    if (method == NULL)
        goto restore;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL)
        goto restore;

    if (wolfSSL_CTX_use_certificate_buffer(ctx, server_cert_der_2048,
            sizeof_server_cert_der_2048, WOLFSSL_FILETYPE_ASN1) !=
            WOLFSSL_SUCCESS)
        goto restore;
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, server_key_der_2048,
            sizeof_server_key_der_2048, WOLFSSL_FILETYPE_ASN1) !=
            WOLFSSL_SUCCESS)
        goto restore;

    /* Same installation as examples/server/server.c and
     * examples/echoserver/echoserver.c under HAVE_TEST_SESSION_TICKET. */
    if (TicketInit() != 0)
        goto restore;
    ticket_ready = 1;
    memset(&ticket_ctx, 0, sizeof(ticket_ctx));
    if (wolfSSL_CTX_set_TicketEncCb(ctx, myTicketEncCb) != WOLFSSL_SUCCESS)
        goto restore;
    if (wolfSSL_CTX_set_TicketEncCtx(ctx, &ticket_ctx) != WOLFSSL_SUCCESS)
        goto restore;

    wolfSSL_CTX_SetIORecv(ctx, io_recv);
    wolfSSL_CTX_SetIOSend(ctx, io_send);

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
        goto restore;
    io.data = record;
    io.len = record_len;
    io.off = 0;
    wolfSSL_SetIOReadCtx(ssl, &io);
    wolfSSL_SetIOWriteCtx(ssl, &io);

    {
        int acc = wolfSSL_accept(ssl);
        int err = wolfSSL_get_error(ssl, acc);
        fprintf(stderr, "  accept=%d error=%d (%s)\n", acc, err,
                wolfSSL_ERR_error_string(err, NULL));
    }
    fflush(stdout);
    rc = 2;

restore:
    if (saved_out >= 0) {
        fflush(stdout);
        dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
        saved_out = -1;
    }
    if (logf != NULL) {
        fflush(logf);
        if (fseek(logf, 0, SEEK_SET) == 0) {
            while (total < captured_cap - 1) {
                nread = (int)fread(captured + total, 1,
                                   (size_t)(captured_cap - 1 - total), logf);
                if (nread <= 0)
                    break;
                total += nread;
            }
        }
        captured[total] = '\0';
        fclose(logf);
        logf = NULL;
    }

    if (rc == 2) {
        char* line = strstr(captured, kLogPrefix);
        if (line == NULL) {
            rc = 2;
        }
        else {
            char* name = line + (int)strlen(kLogPrefix);
            if (strlen(name) >= 16 &&
                    memcmp(name, "AAAAAAAAAAAAAAAA", 16) == 0 &&
                    name[16] == '\n')
                rc = 0;
            else {
                fprintf(stderr, "  logged %zu bytes after the prefix\n",
                        strlen(name) > 0 && name[strlen(name) - 1] == '\n'
                        ? strlen(name) - 1 : strlen(name));
                rc = 1;
            }
        }
    }

done:
    if (ssl != NULL)
        wolfSSL_free(ssl);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    if (ticket_ready)
        TicketCleanup();
    if (logf != NULL)
        fclose(logf);
    if (saved_out >= 0) {
        dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    return rc;
}

static int child_status_is_signal(int status, int sig)
{
    return WIFSIGNALED(status) && WTERMSIG(status) == sig;
}

/* Run one ClientHello in a child so a faulting printf cannot kill the suite
 * before the result is recorded. */
static int run_case(const char* label, const unsigned char* record, int record_len)
{
    int fd[2];
    pid_t pid;
    int status;
    char captured[8192];
    char child_cap[8192];
    int nread;
    int total = 0;
    int rc;

    fprintf(stderr, "CASE %s record_len=%d\n", label, record_len);
    if (record_len > 9) {
        unsigned rec = ((unsigned)record[3] << 8) | record[4];
        unsigned hs = ((unsigned)record[6] << 16) | ((unsigned)record[7] << 8) |
                      record[8];
        fprintf(stderr, "  wire rec=%u hs=%u\n", rec, hs);
    }
    if (pipe(fd) != 0)
        return 3;
    pid = fork();
    if (pid < 0)
        return 3;
    if (pid == 0) {
        close(fd[0]);
        rc = drive_server(record, record_len, captured, (int)sizeof(captured));
        if (write(fd[1], &rc, sizeof(rc)) != (ssize_t)sizeof(rc))
            _exit(3);
        if (write(fd[1], captured, strlen(captured)) < 0)
            _exit(3);
        _exit(0);
    }
    close(fd[1]);
    if (read(fd[0], &rc, sizeof(rc)) != (ssize_t)sizeof(rc))
        rc = -1;
    while (total < (int)sizeof(child_cap) - 1) {
        nread = (int)read(fd[0], child_cap + total,
                          sizeof(child_cap) - 1 - (size_t)total);
        if (nread <= 0)
            break;
        total += nread;
    }
    child_cap[total] = '\0';
    close(fd[0]);
    if (waitpid(pid, &status, 0) < 0)
        return 3;

    fprintf(stderr, "  child status=%d rc=%d\n", status, rc);
    fprintf(stderr, "  stdout: %s\n", child_cap);
    if (child_status_is_signal(status, SIGSEGV) ||
            child_status_is_signal(status, SIGABRT) ||
            child_status_is_signal(status, SIGBUS)) {
        fprintf(stderr, "  FAIL: callback walked off the input buffer\n");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || rc < 0) {
        fprintf(stderr, "  FAIL: harness error\n");
        return 3;
    }
    if (rc == 0) {
        fprintf(stderr, "  PASS: logged name is exactly 16 bytes\n");
        return 0;
    }
    if (rc == 1) {
        fprintf(stderr, "  FAIL: log includes bytes past the 16-byte key name\n");
        return 1;
    }
    fprintf(stderr, "  callback log line was not produced\n");
    return 2;
}

int main(void)
{
    unsigned char ticket[SESSION_TICKET_LEN];
    unsigned char record[8192];
    int ticket_len;
    int record_len;
    int failures = 0;
    int saw_callback = 0;
    unsigned int min_in;
    unsigned int wide_in;
    int rc;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed\n");
        return 3;
    }

    fprintf(stderr,
            "sizes internal=%u enc_max=%u fixed=%u session_max=%d\n",
            (unsigned)WOLFSSL_INTERNAL_TICKET_LEN,
            (unsigned)WOLFSSL_TICKET_ENC_SZ,
            (unsigned)WOLFSSL_TICKET_FIXED_SZ,
            SESSION_TICKET_LEN);

    min_in = (unsigned)WOLFSSL_INTERNAL_TICKET_LEN;
    ticket_len = build_ticket(ticket, (int)sizeof(ticket), min_in);
    if (ticket_len < 0) {
        fprintf(stderr, "could not build minimum ticket\n");
        return 3;
    }
    fprintf(stderr, "minimum ticket in_len=%u ticket_len=%d enc_len=%02x %02x\n",
            min_in, ticket_len, ticket[32], ticket[33]);

    record_len = build_tls12_ticket_record(record, (int)sizeof(record),
                                           ticket, ticket_len);
    if (record_len < 0)
        return 3;
    rc = run_case("tls12-session-ticket", record, record_len);
    if (rc == 1)
        failures++;
    else if (rc == 0)
        saw_callback = 1;
    else if (rc != 2)
        return rc;

    record_len = build_tls13_psk_record(record, (int)sizeof(record),
                                        ticket, ticket_len);
    if (record_len < 0)
        return 3;
    rc = run_case("tls13-psk-identity", record, record_len);
    if (rc == 1)
        failures++;
    else if (rc == 0)
        saw_callback = 1;
    else if (rc != 2)
        return rc;

    /* Largest ciphertext length whose two-byte encoding contains no 0x00,
     * when the server will still accept it. 0x0101 is the smallest such
     * value. A smaller maximum forces a 0x00 into enc_len before the
     * callback. */
    wide_in = 0x0101u;
    if (wide_in <= (unsigned)WOLFSSL_TICKET_ENC_SZ &&
            wide_in + (unsigned)WOLFSSL_TICKET_FIXED_SZ <=
            (unsigned)SESSION_TICKET_LEN) {
        ticket_len = build_ticket(ticket, (int)sizeof(ticket), wide_in);
        if (ticket_len < 0)
            return 3;
        fprintf(stderr, "wide ticket in_len=%u ticket_len=%d enc_len=%02x %02x\n",
                wide_in, ticket_len, ticket[32], ticket[33]);
        record_len = build_tls12_ticket_record(record, (int)sizeof(record),
                                               ticket, ticket_len);
        if (record_len < 0)
            return 3;
        rc = run_case("tls12-no-zero-enc-len", record, record_len);
        if (rc == 1)
            failures++;
        else if (rc == 0)
            saw_callback = 1;
        else if (rc != 2)
            return rc;

        record_len = build_tls13_psk_record(record, (int)sizeof(record),
                                            ticket, ticket_len);
        if (record_len < 0)
            return 3;
        rc = run_case("tls13-no-zero-enc-len", record, record_len);
        if (rc == 1)
            failures++;
        else if (rc == 0)
            saw_callback = 1;
        else if (rc != 2)
            return rc;
    }
    else {
        fprintf(stderr,
                "wide ticket rejected by size limits before the callback "
                "(enc_max=%u)\n",
                (unsigned)WOLFSSL_TICKET_ENC_SZ);
    }

    wolfSSL_Cleanup();

    if (!saw_callback && failures == 0) {
        fprintf(stderr, "callback was never reached\n");
        return 3;
    }
    if (failures != 0) {
        fprintf(stderr, "%d case(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "all reached cases logged a 16-byte name\n");
    return 0;
}

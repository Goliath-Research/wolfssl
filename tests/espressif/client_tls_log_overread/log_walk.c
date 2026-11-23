#include "stubs/esp_log.h"
#include "log_walk.h"

#include <ctype.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Defined by the driver. Leaving here skips the sample's shutdown loop,
 * which spins while any unread application byte remains. The overread
 * happens in this function, before that loop. */
extern jmp_buf tls_task_return;

int g_server_response_logged;
size_t g_server_response_strlen;
unsigned char g_server_response_bytes[256];

void log_walk_reset(void)
{
    g_server_response_logged = 0;
    g_server_response_strlen = 0;
    memset(g_server_response_bytes, 0, sizeof(g_server_response_bytes));
}

uint32_t esp_log_timestamp(void)
{
    return 0;
}

/* Same decision as newlib 4.3.0 vfprintf case 's' (esp-4.3.0
 * newlib/libc/stdio/vfprintf.c): a precision uses memchr, otherwise strlen.
 * ESP-IDF v5.2.3 esp_log_writev passes the ESP_LOGI format to vprintf, and
 * LOG_FORMAT does not give the application %s a precision. */
static size_t newlib_percent_s_length(const char *cp, int prec)
{
    size_t size;

    if (prec >= 0) {
        const char *nul = memchr(cp, 0, (size_t)prec);

        if (nul != NULL) {
            size = (size_t)(nul - cp);
        }
        else {
            size = (size_t)prec;
        }
    }
    else {
        size = strlen(cp);
    }
    return size;
}

void esp_log_write(esp_log_level_t level, const char *tag, const char *format, ...)
{
    va_list ap;
    const char *p;
    int response;
    int saw_string = 0;
    size_t last_len = 0;
    const char *last_str = NULL;

    (void)level;
    (void)tag;
    response = (format != NULL) && (strstr(format, "Server response:") != NULL);

    va_start(ap, format);
    for (p = format; p != NULL && *p != '\0'; p++) {
        int prec = -1;
        int is_long = 0;
        char conv;

        if (*p != '%') {
            continue;
        }
        p++;
        if (*p == '%') {
            continue;
        }
        while (*p != '\0' && strchr("-+ #0", *p) != NULL) {
            p++;
        }
        while (*p != '\0' && isdigit((unsigned char)*p)) {
            p++;
        }
        if (*p == '.') {
            p++;
            prec = 0;
            while (*p != '\0' && isdigit((unsigned char)*p)) {
                prec = prec * 10 + (*p - '0');
                p++;
            }
        }
        if (*p == 'l') {
            is_long = 1;
            p++;
            if (*p == 'l') {
                p++;
            }
        }
        else if (*p == 'z' || *p == 'h') {
            p++;
        }
        conv = *p;
        if (conv == '\0') {
            break;
        }
        if (conv == 's') {
            char *str = va_arg(ap, char *);
            size_t n = newlib_percent_s_length(str, prec);

            saw_string = 1;
            last_len = n;
            last_str = str;
        }
        else if (conv == 'd' || conv == 'i' || conv == 'c') {
            if (is_long) {
                (void)va_arg(ap, long);
            }
            else {
                (void)va_arg(ap, int);
            }
        }
        else if (conv == 'u' || conv == 'x' || conv == 'X' || conv == 'o') {
            if (is_long) {
                (void)va_arg(ap, unsigned long);
            }
            else {
                (void)va_arg(ap, unsigned);
            }
        }
        else if (conv == 'p') {
            (void)va_arg(ap, void *);
        }
    }
    va_end(ap);

    /* LOG_FORMAT's first %s is the tag. The application buffer is the last
     * %s in "Server response: \n\n%s\n". */
    if (response && saw_string && last_str != NULL) {
        size_t copy = last_len;

        g_server_response_logged = 1;
        g_server_response_strlen = last_len;
        if (copy > sizeof(g_server_response_bytes)) {
            copy = sizeof(g_server_response_bytes);
        }
        memcpy(g_server_response_bytes, last_str, copy);
        longjmp(tls_task_return, 1);
    }
}

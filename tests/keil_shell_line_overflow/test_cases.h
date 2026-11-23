/* Assertions shared by both Keil shell copies.
 * These fail while the reader writes one past the caller's buffer, or while
 * getline indexes two characters before the end of a one-character line.
 */
#ifndef KEIL_SHELL_TEST_CASES_H
#define KEIL_SHELL_TEST_CASES_H

#include <stdio.h>
#include <string.h>

static int failures;

static void expect(int cond, const char *name)
{
    if (!cond) {
        printf("FAIL %s\n", name);
        failures++;
    } else {
        printf("PASS %s\n", name);
    }
    fflush(stdout);
}

static void fill_window(unsigned char *raw, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; i++)
        raw[i] = 0xA5;
}

/* 98 payload bytes then newline: terminator lands at index 99, inside. */
static void case_newline_still_fits(const char *tag)
{
    unsigned char raw[1 + 100 + 1];
    unsigned char input[99];
    char *line = (char *)(raw + 1);
    int i;

    fill_window(raw, sizeof raw);
    for (i = 0; i < 98; i++)
        input[i] = 'A';
    input[98] = '\n';
    feed_set(input, 99);
    wolfssl_fgets(line, 100, stdin);
    expect(raw[0] == 0xA5 && raw[101] == 0xA5 && feed_overrun == 0,
           tag);
}

/* Newline is the 100th byte stored. The reader must not write index 100. */
static void case_newline_on_last_slot(const char *tag, char nl)
{
    unsigned char raw[1 + 100 + 1];
    unsigned char input[100];
    char *line = (char *)(raw + 1);
    int i;

    fill_window(raw, sizeof raw);
    for (i = 0; i < 99; i++)
        input[i] = 'B';
    input[99] = (unsigned char)nl;
    feed_set(input, 100);
    wolfssl_fgets(line, 100, stdin);
    expect(raw[101] == 0xA5 && raw[0] == 0xA5 && feed_overrun == 0, tag);
}

/* Enter alone. The byte before the buffer is '&', which getline would
 * rewrite if it looks at strlen-2. A short command must still parse. */
static void case_blank_line_and_short_command(const char *tag_blank,
                                              const char *tag_cr,
                                              const char *tag_short,
                                              const char *tag_bg)
{
    unsigned char raw[1 + 100 + 1];
    char *line = (char *)(raw + 1);
    func_args args;
    int bf = -1;
    unsigned char nl = '\n';
    unsigned char cr = '\r';
    const unsigned char help[] = { 'h', 'e', 'l', 'p', '\n' };
    const unsigned char bg[] = { 'h', 'e', 'l', 'p', ' ', '&', '\n' };

    fill_window(raw, sizeof raw);
    raw[0] = '&';
    feed_set(&nl, 1);
    shell_getline(line, 100, &args, &bf);
    if (raw[0] != '&')
        printf("  byte before buffer is 0x%02x\n", raw[0]);
    expect(raw[0] == '&' && raw[101] == 0xA5 && feed_overrun == 0, tag_blank);

    fill_window(raw, sizeof raw);
    raw[0] = '&';
    feed_set(&cr, 1);
    bf = -1;
    shell_getline(line, 100, &args, &bf);
    expect(raw[0] == '&' && raw[101] == 0xA5 && feed_overrun == 0,
           tag_cr);

    fill_window(raw, sizeof raw);
    feed_set(help, sizeof help);
    bf = -1;
    shell_getline(line, 100, &args, &bf);
    expect(feed_overrun == 0 && raw[0] == 0xA5 && raw[101] == 0xA5 &&
           line[0] == 'h' && line[1] == 'e' && bf == FOREGROUND,
           tag_short);

    fill_window(raw, sizeof raw);
    feed_set(bg, sizeof bg);
    bf = -1;
    shell_getline(line, 100, &args, &bf);
    expect(feed_overrun == 0 && raw[0] == 0xA5 && raw[101] == 0xA5 &&
           bf == BACKGROUND, tag_bg);
}

/* Same Enter-only line, but the caller's object is exactly 100 bytes so a
 * store at index 100 or index -1 is outside that object. */
static void case_exact_buffer(const char *tag_past, const char *tag_before)
{
    char exact[100];
    unsigned char nl = '\n';
    func_args args;
    int bf = -1;
    int i;

    for (i = 0; i < 99; i++)
        exact[i] = 'C';
    {
        unsigned char input[100];
        for (i = 0; i < 99; i++)
            input[i] = 'C';
        input[99] = '\n';
        feed_set(input, 100);
        wolfssl_fgets(exact, 100, stdin);
    }
    expect(feed_overrun == 0, tag_past);

    feed_set(&nl, 1);
    shell_getline(exact, 100, &args, &bf);
    expect(feed_overrun == 0, tag_before);
}

static int run_shell_cases(const char *which)
{
    char name[96];

    failures = 0;

    snprintf(name, sizeof name, "%s newline still inside buffer", which);
    case_newline_still_fits(name);

    snprintf(name, sizeof name, "%s newline on last slot stays inside", which);
    case_newline_on_last_slot(name, '\n');

    snprintf(name, sizeof name, "%s CR on last slot stays inside", which);
    case_newline_on_last_slot(name, '\r');

    {
        char blank[80], blank_cr[80], shortn[80], bg[80];
        snprintf(blank, sizeof blank, "%s blank line does not write before buffer", which);
        snprintf(blank_cr, sizeof blank_cr, "%s CR-only line does not write before buffer", which);
        snprintf(shortn, sizeof shortn, "%s short command stays inside and is foreground", which);
        snprintf(bg, sizeof bg, "%s trailing ampersand stays inside and is background", which);
        case_blank_line_and_short_command(blank, blank_cr, shortn, bg);
    }

    snprintf(name, sizeof name, "%s exact 100-byte buffer newline on last slot", which);
    {
        char before[96];
        snprintf(before, sizeof before, "%s exact 100-byte buffer blank line", which);
        case_exact_buffer(name, before);
    }

    printf("%s: %d failure(s)\n", which, failures);
    return failures == 0 ? 0 : 1;
}

#endif

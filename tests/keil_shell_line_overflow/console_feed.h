/* Host stand-in for the Keil debug console, built from the retarget the
 * MDK5 sample selects (Keil::ARM_Compiler 1.0.0, STDIN variant ITM):
 *
 *   ITM_ReceiveChar returns ITM_RxBuffer and then marks it empty
 *     (Source/retarget_io.c, ITM_ReceiveChar).
 *   stdin_getchar waits until that returns a character
 *     (Source/retarget_io.c, stdin_getchar under RTE_Compiler_IO_STDIN_ITM).
 *   _sys_read of STDIN copies that one byte and does not modify it
 *     (Source/retarget_io.c, _sys_read case FH_STDIN).
 *
 * The project file selects that component and does not use microlib, so the
 * C library getchar path is _sys_read rather than the microlib fgetc.
 * The typed character is placed in ITM_RxBuffer before the read, which is
 * the write the retarget comment attributes to the debugger.
 */
#ifndef KEIL_SHELL_CONSOLE_FEED_H
#define KEIL_SHELL_CONSOLE_FEED_H

#include <stdint.h>

#define ITM_RXBUFFER_EMPTY 0x5AA55AA5

volatile int32_t ITM_RxBuffer = ITM_RXBUFFER_EMPTY;

static const unsigned char *feed_p;
static const unsigned char *feed_end;
static int feed_overrun;

int32_t ITM_ReceiveChar(void)
{
    int32_t ch = -1;

    if (ITM_RxBuffer != ITM_RXBUFFER_EMPTY) {
        ch = ITM_RxBuffer;
        ITM_RxBuffer = ITM_RXBUFFER_EMPTY;
    }
    return ch;
}

static int stdin_getchar_itm(void)
{
    int32_t ch;

    do {
        ch = ITM_ReceiveChar();
        if (ch == -1) {
            if (feed_p >= feed_end) {
                feed_overrun = 1;
                return '\n';
            }
            ITM_RxBuffer = *feed_p++;
        }
    } while (ch == -1);
    return (int)ch;
}

static int test_getchar(void)
{
    unsigned char buf[1];
    int ch = stdin_getchar_itm();

    if (ch < 0)
        return '\n';
    buf[0] = (unsigned char)ch;
    return buf[0];
}

static int test_putchar(int c)
{
    (void)c;
    return c;
}

static void feed_set(const unsigned char *p, unsigned n)
{
    feed_p = p;
    feed_end = p + n;
    feed_overrun = 0;
    ITM_RxBuffer = ITM_RXBUFFER_EMPTY;
}

#endif

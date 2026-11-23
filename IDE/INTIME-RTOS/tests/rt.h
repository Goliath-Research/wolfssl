/* Test-only stand-in for the INtime <rt.h> declarations wolfExamples.c includes.
 * The TLS client under test does not call these; they exist so the rest of
 * the sample translation unit can be compiled and linked on Linux. */
#ifndef INTIME_RT_STUB_H
#define INTIME_RT_STUB_H

#include <errno.h>

typedef int RTHANDLE;
typedef unsigned int DWORD;
typedef int BOOLEAN;
typedef char *LPSTR;
typedef void (*LPPROC)(void *);

#define BAD_RTHANDLE ((RTHANDLE)-1)
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#define NO_WAIT 0
#define WAIT_FOREVER 0xFFFFFFFFu
#define NULL_RTHANDLE ((RTHANDLE)0)
#define THIS_THREAD 1
#define THIS_PROCESS 2
#define ROOT_PROCESS 3
#define THREAD_HANDLER 0
#define INVALID_TYPE 0
#define TERMINATE 1
#define RT_SYSTEM_NOTIFICATIONS 0x1
#define RT_EXIT_NOTIFICATIONS 0x2
#define NT_HOST_UP 2
#define NT_BLUESCREEN 3
#define KERNEL_STOPPING 4
#define NT_HOST_HIBERNATE 5
#define NT_HOST_STANDBY 6
#define NT_HOST_SHUTDOWN_PENDING 7

typedef struct {
    int ExceptionMode;
} EXCEPTION;

typedef struct {
    int KernelTickRatio;
} SYSINFO;

typedef struct {
    DWORD dwNotifyType;
} EVENTINFO;

static inline BOOLEAN CatalogRtHandle(RTHANDLE a, RTHANDLE b, LPSTR c)
{
    (void)a;
    (void)b;
    (void)c;
    return TRUE;
}

static inline RTHANDLE LookupRtHandle(RTHANDLE a, LPSTR b, DWORD c)
{
    (void)a;
    (void)b;
    (void)c;
    return BAD_RTHANDLE;
}

static inline int GetRtHandleType(RTHANDLE h)
{
    (void)h;
    return INVALID_TYPE;
}

static inline BOOLEAN UncatalogRtHandle(RTHANDLE a, LPSTR b)
{
    (void)a;
    (void)b;
    return TRUE;
}

static inline void GetRtExceptionHandlerInfo(int which, EXCEPTION *eh)
{
    (void)which;
    if (eh != 0)
        eh->ExceptionMode = 0;
}

static inline void SetRtExceptionHandler(EXCEPTION *eh)
{
    (void)eh;
}

static inline RTHANDLE GetRtThreadHandles(int which)
{
    (void)which;
    return (RTHANDLE)1;
}

static inline int SendRtData(RTHANDLE h, void *data, DWORD n)
{
    (void)h;
    (void)data;
    (void)n;
    return 0;
}

static inline BOOLEAN CopyRtSystemInfo(SYSINFO *info)
{
    if (info != 0)
        info->KernelTickRatio = 1;
    return TRUE;
}

static inline int SetRtProcessMaxPriority(RTHANDLE h, int prio)
{
    (void)h;
    (void)prio;
    return 0;
}

static inline RTHANDLE CreateRtThread(int prio, LPPROC proc, DWORD stack, void *arg)
{
    (void)prio;
    (void)proc;
    (void)stack;
    (void)arg;
    return BAD_RTHANDLE;
}

static inline void RtSleep(DWORD ticks)
{
    (void)ticks;
}

static inline BOOLEAN RtNotifyEvent(DWORD flags, DWORD wait, EVENTINFO *info)
{
    (void)flags;
    (void)wait;
    (void)info;
    return FALSE;
}

static inline DWORD GetLastRtError(void)
{
    return 0;
}

static inline const char *GetRtErrorText(DWORD err)
{
    (void)err;
    return "";
}

#endif

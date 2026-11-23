/* Byte-preserving stand-in for the FreeRTOS+TCP calls the RA6M4 and RZN2L
 * samples make. FreeRTOS_recv in FreeRTOS+TCP V4.3.3 (the version named by
 * IDE/Renesas/e2studio/RA6M4/README.md) copies min(available, length) bytes
 * via uxStreamBufferGet's memcpy and returns that count. wolfSSL then calls
 * it through RECV_FUNCTION in wolfssl/wolfio.h. These samples instead pass
 * the socket to wolfSSL_set_fd, and the library built for this test uses
 * POSIX recv, which has the same copy-and-count contract. FreeRTOS_recv is
 * still provided so a FREERTOS_TCP build of the library would hit it.
 *
 * The address passed by the sample is logged. The TCP connection is made to
 * 127.0.0.1 on that port because this host cannot claim the sample LAN address.
 */
#include "FreeRTOS_Sockets.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

BaseType_t FreeRTOS_IPInit(const uint8_t *ip, const uint8_t *mask,
    const uint8_t *gw, const uint8_t *dns, const uint8_t *mac)
{
    (void)ip;
    (void)mask;
    (void)gw;
    (void)dns;
    (void)mac;
    return pdPASS;
}

uint16_t FreeRTOS_htons(uint16_t port)
{
    return htons(port);
}

uint32_t FreeRTOS_inet_addr(const char *ip)
{
    return inet_addr(ip);
}

static void set_timeouts(int fd)
{
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

xSocket_t FreeRTOS_socket(int domain, int type, int protocol)
{
    int fd;

    (void)domain;
    (void)type;
    (void)protocol;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return FREERTOS_INVALID_SOCKET;
    }
    set_timeouts(fd);
    return fd;
}

BaseType_t FreeRTOS_bind(xSocket_t sock, void *addr, size_t addrlen)
{
    (void)sock;
    (void)addr;
    (void)addrlen;
    return 0;
}

BaseType_t FreeRTOS_connect(xSocket_t sock, struct freertos_sockaddr *addr,
    size_t addrlen)
{
    struct sockaddr_in local;
    struct in_addr printed;
    char dotted[INET_ADDRSTRLEN];

    (void)addrlen;
    if (addr == NULL || sock < 0) {
        return -1;
    }

    printed.s_addr = addr->sin_addr;
    if (inet_ntop(AF_INET, &printed, dotted, sizeof(dotted)) == NULL) {
        snprintf(dotted, sizeof(dotted), "invalid");
    }
    fprintf(stderr, "DIAL %s %u\n", dotted, (unsigned)ntohs(addr->sin_port));
    fflush(stderr);

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = addr->sin_port;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(sock, (struct sockaddr *)&local, sizeof(local)) != 0) {
        fprintf(stderr, "CONNECT_FAIL %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

BaseType_t FreeRTOS_recv(xSocket_t sock, void *buf, size_t len, BaseType_t flags)
{
    int n;

    (void)flags;
    if (sock < 0 || buf == NULL) {
        return -1;
    }
    n = (int)recv(sock, buf, len, 0);
    if (n < 0) {
        return -1;
    }
    return n;
}

BaseType_t FreeRTOS_send(xSocket_t sock, const void *buf, size_t len,
    BaseType_t flags)
{
    int off = 0;
    const char *p = (const char *)buf;

    (void)flags;
    if (sock < 0 || buf == NULL) {
        return -1;
    }
    while ((size_t)off < len) {
        int n = (int)send(sock, p + off, len - (size_t)off, 0);
        if (n <= 0) {
            return -1;
        }
        off += n;
    }
    return off;
}

BaseType_t FreeRTOS_shutdown(xSocket_t sock, int how)
{
    if (sock >= 0) {
        shutdown(sock, how);
    }
    return 0;
}

BaseType_t FreeRTOS_closesocket(xSocket_t sock)
{
    if (sock >= 0) {
        close(sock);
    }
    return 0;
}

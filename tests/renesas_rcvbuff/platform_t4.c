/* Byte-preserving stand-in for Renesas T4 tcp_* used by the sample clients.
 * tcp_rcv_dat copies at most `len` bytes of the TCP stream and returns the
 * count (ITRON tcp_rcv_dat; T4 _tcp_cpy_rwdat memcpy). This file does the
 * same with recv/send. The dialed address is logged, then the socket is
 * connected to 127.0.0.1 on that same port because this host cannot claim
 * the sample's LAN address.
 */
#include "r_t4_itcpip.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int g_fd = -1;

static void set_timeouts(int fd)
{
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

ER tcp_con_cep(ID cepid, T_IPV4EP *myaddr, T_IPV4EP *dstaddr, TMO tmout)
{
    struct sockaddr_in local;
    unsigned long ip;
    int fd;

    (void)cepid;
    (void)myaddr;
    (void)tmout;

    if (dstaddr == NULL) {
        return -1;
    }

    ip = dstaddr->ipaddr;
    fprintf(stderr, "DIAL %lu.%lu.%lu.%lu %u\n",
        (ip >> 24) & 0xffUL, (ip >> 16) & 0xffUL,
        (ip >> 8) & 0xffUL, ip & 0xffUL,
        (unsigned)dstaddr->portno);
    fflush(stderr);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    set_timeouts(fd);

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(dstaddr->portno);
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        fprintf(stderr, "CONNECT_FAIL %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    if (g_fd >= 0) {
        close(g_fd);
    }
    g_fd = fd;
    return E_OK;
}

ER tcp_rcv_dat(ID cepid, VP data, INT len, TMO tmout)
{
    int n;

    (void)cepid;
    (void)tmout;
    if (g_fd < 0 || data == NULL || len < 0) {
        return -1;
    }
    n = (int)recv(g_fd, data, (size_t)len, 0);
    if (n < 0) {
        return -1;
    }
    return n;
}

ER tcp_snd_dat(ID cepid, VP data, INT len, TMO tmout)
{
    int off = 0;
    const char *p = (const char *)data;

    (void)cepid;
    (void)tmout;
    if (g_fd < 0 || data == NULL || len < 0) {
        return -1;
    }
    while (off < len) {
        int n = (int)send(g_fd, p + off, (size_t)(len - off), 0);
        if (n <= 0) {
            return -1;
        }
        off += n;
    }
    return off;
}

ER tcp_sht_cep(ID cepid)
{
    (void)cepid;
    if (g_fd >= 0) {
        shutdown(g_fd, SHUT_RDWR);
    }
    return E_OK;
}

ER tcp_cls_cep(ID cepid, TMO tmout)
{
    (void)cepid;
    (void)tmout;
    if (g_fd >= 0) {
        close(g_fd);
        g_fd = -1;
    }
    return E_OK;
}

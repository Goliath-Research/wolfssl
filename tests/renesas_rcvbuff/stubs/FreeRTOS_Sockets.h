#ifndef FREERTOS_SOCKETS_STUB_H
#define FREERTOS_SOCKETS_STUB_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>

#include "FreeRTOS_IP.h"

typedef int xSocket_t;
typedef int Socket_t;
typedef uint32_t TickType_t;

#define FREERTOS_INVALID_SOCKET ((xSocket_t)-1)
#define FREERTOS_AF_INET 2
#define FREERTOS_SOCK_STREAM 1
#define FREERTOS_IPPROTO_TCP 6
#define FREERTOS_SHUT_RDWR 2

struct freertos_sockaddr {
    uint16_t sin_port;
    uint32_t sin_addr;
};

uint16_t FreeRTOS_htons(uint16_t port);
uint32_t FreeRTOS_inet_addr(const char *ip);
xSocket_t FreeRTOS_socket(int domain, int type, int protocol);
BaseType_t FreeRTOS_bind(xSocket_t sock, void *addr, size_t addrlen);
BaseType_t FreeRTOS_connect(xSocket_t sock, struct freertos_sockaddr *addr,
    size_t addrlen);
BaseType_t FreeRTOS_recv(xSocket_t sock, void *buf, size_t len, BaseType_t flags);
BaseType_t FreeRTOS_send(xSocket_t sock, const void *buf, size_t len,
    BaseType_t flags);
BaseType_t FreeRTOS_shutdown(xSocket_t sock, int how);
BaseType_t FreeRTOS_closesocket(xSocket_t sock);

#endif

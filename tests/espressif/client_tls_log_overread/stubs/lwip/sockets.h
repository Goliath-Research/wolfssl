/* POSIX sockets under the lwIP header names the sample includes. */
#ifndef LWIP_SOCKETS_H_STUB_
#define LWIP_SOCKETS_H_STUB_
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
struct ip4_addr {
    uint32_t addr;
};
#endif

/* Plain TCP peer for simple_tcp_client.c. Same length contract as the TLS
 * server: write exactly nbytes, with no terminator inside a full-size buffer.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int nbytes;
    int port;
    int listen_fd;
    int conn;
    int opt = 1;
    int off;
    struct sockaddr_in addr;
    unsigned char payload[256];
    unsigned char inbuf[64];

    if (argc != 3) {
        fprintf(stderr, "usage: tcp_payload_server nbytes port\n");
        return 2;
    }
    nbytes = atoi(argv[1]);
    port = atoi(argv[2]);
    if (nbytes < 1 || nbytes > (int)sizeof(payload) || port <= 0) {
        return 2;
    }
    if (nbytes == 4) {
        memcpy(payload, "pong", 4);
    }
    else {
        memset(payload, 'A', (size_t)nbytes);
    }

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }
    (void)setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        return 1;
    }
    if (listen(listen_fd, 1) != 0) {
        perror("listen");
        return 1;
    }
    fprintf(stderr, "SERVER_READY\n");
    fflush(stderr);

    conn = accept(listen_fd, NULL, NULL);
    if (conn < 0) {
        perror("accept");
        return 1;
    }
    (void)recv(conn, inbuf, sizeof(inbuf), 0);
    off = 0;
    while (off < nbytes) {
        int n = (int)send(conn, payload + off, (size_t)(nbytes - off), 0);
        if (n <= 0) {
            perror("send");
            return 1;
        }
        off += n;
    }
    fprintf(stderr, "SERVER_WROTE %d\n", off);
    fflush(stderr);
    shutdown(conn, SHUT_RDWR);
    close(conn);
    close(listen_fd);
    return 0;
}

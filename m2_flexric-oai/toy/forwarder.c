// sctp_forwarder.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

#define LISTEN_PORT 15001
#define FORWARD_IP "127.0.0.1"
#define FORWARD_PORT 36422
#define BUFFER_SIZE 2048

int main() {
    int listen_fd, conn_fd, forward_fd;
    struct sockaddr_in listen_addr, client_addr, forward_addr;
    socklen_t addr_len;
    char buffer[BUFFER_SIZE];
    ssize_t recv_len;

    // Create SCTP socket for listening
    listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (listen_fd < 0) {
        perror("socket");
        exit(1);
    }

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(LISTEN_PORT);
    listen_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        exit(1);
    }

    printf("SCTP forwarder listening on port %d...\n", LISTEN_PORT);

    while (1) {
        addr_len = sizeof(client_addr);
        conn_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (conn_fd < 0) {
            perror("accept");
            continue;
        }

        // Connect to the actual destination
        forward_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
        if (forward_fd < 0) {
            perror("forward socket");
            close(conn_fd);
            continue;
        }

        memset(&forward_addr, 0, sizeof(forward_addr));
        forward_addr.sin_family = AF_INET;
        forward_addr.sin_port = htons(FORWARD_PORT);
        inet_pton(AF_INET, FORWARD_IP, &forward_addr.sin_addr);

        if (connect(forward_fd, (struct sockaddr *)&forward_addr, sizeof(forward_addr)) < 0) {
            perror("forward connect");
            close(conn_fd);
            close(forward_fd);
            continue;
        }

        printf("Forwarding between client and 127.0.0.1:%d\n", FORWARD_PORT);

        while ((recv_len = recv(conn_fd, buffer, BUFFER_SIZE, 0)) > 0) {
            send(forward_fd, buffer, recv_len, 0);
            recv_len = recv(forward_fd, buffer, BUFFER_SIZE, 0);
            if (recv_len <= 0) break;
            send(conn_fd, buffer, recv_len, 0);
        }

        close(conn_fd);
        close(forward_fd);
    }

    close(listen_fd);
    return 0;
}

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>

#ifdef __linux__
#include <netpacket/packet.h>
#include <net/if.h>
#elif defined(__APPLE__)
#include <net/if_dl.h>
#endif

#define PRINT_ERROR(error, ...) \
    printf("\033[31m" error "\033[0m\n", ##__VA_ARGS__)

enum ConnectionType {
    Server,
    Client
};

extern char private_ip_address_testing[INET_ADDRSTRLEN];

static inline int get_private_ip_from_socket() {
    const int temp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (temp_socket < 0) {
        PRINT_ERROR("Failed to create temp socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in remote = {0};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &remote.sin_addr);

    if (connect(temp_socket, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
        PRINT_ERROR("Failed to connect temp socket");
        close(temp_socket);
        exit(EXIT_FAILURE);
    }

    struct sockaddr private_sockaddr;
    socklen_t private_sockaddr_len = sizeof(private_sockaddr);

    if(getsockname(temp_socket, &private_sockaddr, &private_sockaddr_len) == -1) {
        PRINT_ERROR("Failed to get private ip address");
        close(temp_socket);
        exit(EXIT_FAILURE);
    }

    if(!inet_ntop(AF_INET, &((struct sockaddr_in *)&private_sockaddr)->sin_addr, private_ip_address_testing, sizeof(private_ip_address_testing))) {
        exit(EXIT_FAILURE);
    };

    printf("Private ip: %s\n", private_ip_address_testing);

    return 0;
}

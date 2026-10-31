#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#ifdef __linux__
#include <netpacket/packet.h>
#include <net/if.h>

#define MAX_INTERFACE_LEN 16
#elif defined(__APPLE__)
#include <net/if_dl.h>

#define MAX_INTERFACE_LEN 16
#elif defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>

#define MAX_INTERFACE_LEN 128
#endif

enum ConnectionType {
    CONNECTION_TYPE_SERVER,
    CONNECTION_TYPE_CLIENT
};

#define PRINT_ERROR(error, ...) \
    printf("\033[31m" error "\033[0m\n", ##__VA_ARGS__);

#define PRINT_SUCCESS(error, ...) \
    printf("\033[32m" error "\033[0m\n", ##__VA_ARGS__);

extern char private_ip_address_testing[MAX_INTERFACE_LEN];

#if defined(__APPLE__) || defined(__linux__)
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static inline int get_private_ip_from_socket(void) {
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
#elif defined(_WIN32)
static inline int get_private_ip_from_socket(void) {
    const SOCKET temp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (temp_socket == INVALID_SOCKET) {
        PRINT_ERROR("Failed to create temp socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in remote = {0};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(53);

    if (inet_pton(AF_INET, "8.8.8.8", &remote.sin_addr) != 1) {
        PRINT_ERROR("Failed to parse remote IP");
        closesocket(temp_socket);
        exit(EXIT_FAILURE);
    }

    if (connect(temp_socket, (struct sockaddr *)&remote, sizeof(remote)) == SOCKET_ERROR) {
        PRINT_ERROR("Failed to connect temp socket");
        closesocket(temp_socket);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in private_sockaddr = {0};
    int private_sockaddr_len = sizeof(private_sockaddr);

    if (getsockname(
            temp_socket,
            (struct sockaddr *)&private_sockaddr,
            &private_sockaddr_len
        ) == SOCKET_ERROR) {
        PRINT_ERROR("Failed to get private IP address");
        closesocket(temp_socket);
        exit(EXIT_FAILURE);
    }

    if (!inet_ntop(
            AF_INET,
            &private_sockaddr.sin_addr,
            private_ip_address_testing,
            sizeof(private_ip_address_testing)
        )) {
        PRINT_ERROR("Failed to convert private IP address");
        closesocket(temp_socket);
        exit(EXIT_FAILURE);
    }

    printf("Private IP: %s\n", private_ip_address_testing);

    closesocket(temp_socket);
    return 0;
}
#endif

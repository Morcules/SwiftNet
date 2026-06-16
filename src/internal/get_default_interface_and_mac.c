#include "internal.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <netpacket/packet.h>
#include <net/if.h>
#elif defined(__APPLE__)
#include <net/if_dl.h>
#endif

int get_default_interface_and_mac(char* restrict interface_name, const uint32_t interface_name_length, uint8_t* restrict mac_out, const int sockfd) {
    struct sockaddr_in local_addr;
    socklen_t addr_len;
    char local_ip[INET_ADDRSTRLEN];
    struct ifaddrs* ifaddr;
    struct ifaddrs* ifa;
    struct ifaddrs* match;
    int mac_found;


    addr_len = sizeof(local_addr);

    if(getsockname(sockfd, (struct sockaddr *)&local_addr, &addr_len) < 0) {
        perror("getsockname");
        return -1;
    }

    if(!inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, sizeof(local_ip))) {
        perror("inet_ntop");
        return -1;
    }

    if(getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    match = NULL;

    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        char iface_ip[INET_ADDRSTRLEN];
        struct sockaddr_in* sin;

        if(!ifa->ifa_addr) {
            continue;
        }

        if(ifa->ifa_addr->sa_family == AF_INET) {
            sin = (struct sockaddr_in *)ifa->ifa_addr;

            if(!inet_ntop(AF_INET, &sin->sin_addr, iface_ip, sizeof(iface_ip))) {
                continue;
            }

            if(strcmp(local_ip, iface_ip) == 0) {
                match = ifa;
                break;
            }
        }
    }

    if(!match) {
        PRINT_ERROR("No matching interface found for IP %s", local_ip);
        freeifaddrs(ifaddr);
        return -1;
    }

    strncpy(interface_name, match->ifa_name, interface_name_length - 1);
    interface_name[interface_name_length - 1] = '\0';

    mac_found = 0;

    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if(!ifa->ifa_addr) {
            continue;
        }

        if(strcmp(ifa->ifa_name, interface_name) != 0) {
            continue;
        }

    #ifdef __linux__
        if(ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll* s;


            s = (struct sockaddr_ll *)ifa->ifa_addr;
            if(s->sll_halen == 6) {
                memcpy(mac_out, s->sll_addr, 6);
                mac_found = 1;
                break;
            }
        }
    #elif defined(__APPLE__)
        if(ifa->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl* sdl;


            sdl = (struct sockaddr_dl *)ifa->ifa_addr;
            if(sdl->sdl_alen == 6) {
                memcpy(mac_out, LLADDR(sdl), 6);
                mac_found = 1;
                break;
            }
        }
    #endif
    }

    freeifaddrs(ifaddr);

    if(!mac_found) {
        PRINT_ERROR("No MAC address found for interface %s", interface_name);
        return -1;
    }

    return 0;
}
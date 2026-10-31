#include "internal.h"

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#ifdef __linux__
#include <netpacket/packet.h>
#include <net/if.h>

#include <ifaddrs.h>
#elif defined(__APPLE__)
#include <net/if_dl.h>

#include <ifaddrs.h>
#elif defined(_WIN32)
#include <winnt.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iptypes.h>
#endif

#if defined(__linux__) || defined(__APPLE__)
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

    printf("Found interface: %s\n", interface_name);

    return 0;
}
#elif defined(_WIN32)
int get_default_interface_and_mac(
    char* restrict interface_name,
    const uint32_t interface_name_length,
    uint8_t* restrict mac_out,
    const int sockfd
) {
    struct sockaddr_in local_addr;
    uint32_t addr_len;
    uint32_t buffer_size;
    uint64_t result;
    IP_ADAPTER_ADDRESSES* adapters;
    IP_ADAPTER_ADDRESSES* adapter;
    IP_ADAPTER_ADDRESSES* match;

    addr_len = sizeof(local_addr);

    if (getsockname((SOCKET)sockfd, (struct sockaddr*)&local_addr, (int*)&addr_len) == SOCKET_ERROR) {
        PRINT_ERROR("getsockname failed: %d", WSAGetLastError());
        return -1;
    }

    buffer_size = 15000;
    adapters = NULL;

    for (;;) {
        adapters = malloc(buffer_size);

        if (!adapters) {
            return -1;
        }

        result = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_SKIP_ANYCAST |
            GAA_FLAG_SKIP_MULTICAST |
            GAA_FLAG_SKIP_DNS_SERVER,
            NULL,
            adapters,
            (unsigned long*)&buffer_size
        );

        if (result != ERROR_BUFFER_OVERFLOW) {
            break;
        }

        free(adapters);
        adapters = NULL;
    }

    if (result != NO_ERROR) {
        PRINT_ERROR("GetAdaptersAddresses failed: %lu", (unsigned long)result);
        free(adapters);
        return -1;
    }

    match = NULL;

    for (adapter = adapters; adapter != NULL; adapter = adapter->Next) {
        IP_ADAPTER_UNICAST_ADDRESS* unicast;


        for (unicast = adapter->FirstUnicastAddress; unicast != NULL; unicast = unicast->Next) {

            struct sockaddr_in* sin;

            if (unicast->Address.lpSockaddr == NULL ||
                unicast->Address.lpSockaddr->sa_family != AF_INET) {
                continue;
            }

            sin = (struct sockaddr_in*)unicast->Address.lpSockaddr;

            if (sin->sin_addr.s_addr == local_addr.sin_addr.s_addr) {
                match = adapter;
                break;
            }
        }

        if (match != NULL) {
            break;
        }
    }

    if (match == NULL) {
        PRINT_ERROR("No matching interface found for socket IPv4 address");
        free(adapters);
        return -1;
    }

    snprintf(interface_name, interface_name_length, "\\Device\\NPF_%s", match->AdapterName);

    if (match->PhysicalAddressLength != 6) {
        PRINT_ERROR("Invalid mac adress size");
        free(adapters);
        return -1;
    }

    memcpy(mac_out, match->PhysicalAddress, 6);

    printf("Found interface: %s\n", interface_name);

    free(adapters);
    return 0;
}
#endif

// TODO windows version

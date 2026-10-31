#include "internal.h"
#include <stdatomic.h>
#include <stdint.h>
#include <unistd.h>

// TODO: Windows equivalent
#if defined(__APPLE__) || defined(__linux__)
#include "stdio.h"
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>

uint16_t get_mtu(const char* restrict const net_interface, const int sockfd) {
    struct ifreq ifr;


    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, net_interface, MAX_INTERFACE_LEN - 1);

    if(ioctl(sockfd, SIOCGIFMTU, &ifr) < 0) {
        PRINT_ERROR("ioctl failed");
        exit(EXIT_FAILURE);
    }

    return (uint16_t)ifr.ifr_mtu;
}
#elif defined(_WIN32)
#include <winsock2.h>
#include <iphlpapi.h>

uint16_t get_mtu(const char* restrict const net_interface, const int sockfd) {
    uint32_t buffer_size;
    uint64_t result;
    IP_ADAPTER_ADDRESSES* adapters;
    IP_ADAPTER_ADDRESSES* adapter;
    uint16_t mtu;

    buffer_size = 15000;
    adapters = NULL;

    for (;;) {
        adapters = malloc(buffer_size);

        if (unlikely(adapters == NULL)) {
            exit(EXIT_FAILURE);
        }

        result = GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_ALL_INTERFACES,
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
        PRINT_ERROR("GetAdaptersAddresses failed: %llu", result);
        free(adapters);
        exit(EXIT_FAILURE);
    }

    for (adapter = adapters; adapter != NULL; adapter = adapter->Next) {
        if (strcmp(adapter->AdapterName, net_interface) == 0) {
            mtu = (uint16_t)adapter->Mtu;
            free(adapters);
            return mtu;
        }
    }

    PRINT_ERROR("Interface not found: %s\n", net_interface);
    free(adapters);
    exit(EXIT_FAILURE);
}
#endif

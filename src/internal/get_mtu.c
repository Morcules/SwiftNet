#include "internal.h"
#include "stdlib.h"
#include "stdio.h"
#include <stdatomic.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

const uint32_t get_mtu(const char* restrict const interface, const int sockfd) {
    struct ifreq ifr;


    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if(ioctl(sockfd, SIOCGIFMTU, &ifr) < 0) {
        PRINT_ERROR("ioctl failed");
        exit(EXIT_FAILURE);
    }

    return ifr.ifr_mtu;
}
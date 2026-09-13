#include "../internal.h"
#include <errno.h>
#include <pcap/pcap.h>

int swiftnet_pcap_send(pcap_t* const pcap, const uint8_t* restrict const data, const uint32_t len) {
    int ret;


    ret = pcap_inject(pcap, data, (size_t)len);

    printf("injecting packet\n");

    if(ret == -1) {
        if(errno == ENOBUFS) {
            return -2;
        }

        PRINT_ERROR("inject error: %s", pcap_geterr(pcap));
        return -1;
    }

    return 0;
}

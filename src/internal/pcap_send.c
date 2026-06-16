#include "internal.h"
#include <errno.h>
#include <pcap/pcap.h>

int swiftnet_pcap_send(pcap_t* const pcap, const uint8_t* restrict const data, const int len) {
    int ret;


    ret = pcap_inject(pcap, data, len);

    if(ret == -1) {
        if(errno == ENOBUFS) {
            return -2;
        }

        PRINT_ERROR("inject error: %s", pcap_geterr(pcap));
        return -1;
    }

    return 0;
}

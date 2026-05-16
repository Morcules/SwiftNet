#include "../internal.h"
#include <errno.h>
#include <pcap/pcap.h>

int swiftnet_pcap_send(pcap_t *pcap, const u_char *data, int len) {
    int ret = pcap_inject(pcap, data, len);

    if (ret == -1) {
        if (errno == ENOBUFS) {
            return -2;
        }

        PRINT_ERROR("inject error: %s", pcap_geterr(pcap));
        return -1;
    }

    return 0;
}

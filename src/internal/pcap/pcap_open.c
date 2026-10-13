#include "../internal.h"
#include <pcap/pcap.h>

void swiftnet_pcap_open(const char* const restrict interface, struct SwiftNetNetworkData* const network_data) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* p;
    char filter_exp[] = "ip proto 253";
    bpf_u_int32 net;


    net = 0;

    p = pcap_open_live(
        interface,
        65535,
        1,
        25,
        errbuf
    );

    if(!p) {
        PRINT_ERROR("pcap_open_live failed: %s", errbuf);
        network_data->pcap = NULL;
        return;
    }

    if(pcap_compile(p, &network_data->fp, filter_exp, 0, net) == -1) {
        PRINT_ERROR("Couldn't parse filter %s: %s", filter_exp, pcap_geterr(p));
        exit(EXIT_FAILURE);
    }

    if(pcap_setfilter(p, &network_data->fp) != 0) {
        PRINT_ERROR("Unable to set filter: %s", pcap_geterr(p));
    }

    network_data->pcap = p;
}


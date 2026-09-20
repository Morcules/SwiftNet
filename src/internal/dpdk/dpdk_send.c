#include "../internal.h"

#ifdef SWIFT_NET_BACKEND_DPDK
#include <rte_ethdev.h>

int swiftnet_dpdk_send(const struct SwiftNetNetworkData* const network_data, struct rte_mbuf* buf) {
    struct rte_mbuf* buf_clone = rte_pktmbuf_clone(buf, network_data->mem_pool);

    if(rte_eth_tx_burst(network_data->port, 0, &buf_clone, 1) != 1) {
        rte_pktmbuf_free(buf_clone);
    };

    return 0;
}
#endif

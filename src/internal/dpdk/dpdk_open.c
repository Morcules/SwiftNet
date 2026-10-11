#include <stdint.h>

#include "../networking.h"

#ifdef SWIFT_NET_BACKEND_DPDK
void swiftnet_dpdk_open_port(const uint16_t port, struct SwiftNetNetworkData* const network_data) {
    struct rte_eth_conf port_conf = {0};
    char name[32];

    port_conf.rxmode.mtu = RTE_ETHER_MAX_LEN;

    snprintf(name, sizeof(name), "mbuf_pool_%u", port);

    network_data->mem_pool = rte_pktmbuf_pool_create(name, 1024, 512, 0,RTE_MBUF_DEFAULT_BUF_SIZE, (int)rte_socket_id());

    if (unlikely(network_data->mem_pool == NULL))
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    if (unlikely(rte_eth_dev_configure(port, 1, 1, &port_conf) < 0))
        rte_exit(EXIT_FAILURE, "Cannot configure port\n");

    if (unlikely(rte_eth_rx_queue_setup(port, 0, 128, rte_socket_id(), NULL, network_data->mem_pool) < 0))
        rte_exit(EXIT_FAILURE, "Cannot setup RX queue\n");

    if (unlikely(rte_eth_tx_queue_setup(port, 0, 128, rte_socket_id(), NULL) < 0))
        rte_exit(EXIT_FAILURE, "Cannot setup TX queue\n");

    if (unlikely(rte_eth_dev_start(port) < 0))
        rte_exit(EXIT_FAILURE, "Cannot start port\n");

    rte_eth_promiscuous_enable(port);
}
#endif

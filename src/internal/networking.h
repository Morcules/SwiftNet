#pragma once

#include "../swift_net.h"
#include "internal.h"
#include <stdint.h>
#include <string.h>

#ifdef SWIFT_NET_BACKEND_PCAP

#include <sched.h>
#include <pcap/pcap.h>
    #define WAIT_LISTENER_THREAD(listener) \
        pthread_join((listener)->listener_thread, NULL);

    // Simple crc16 call with proper memory order
    #define HANDLE_CHECKSUM(buffer, size, network_data, packet_metadata) \
        { \
        const uint16_t ip_sum = htons(ip_checksum(buffer + GET_PREPEND_SIZE(network_data))); \
        const uint32_t checksum = crc32(buffer + GET_PREPEND_SIZE(network_data) + sizeof(struct ip), size + sizeof(struct SwiftNetChunkMetadata) + (packet_metadata ? sizeof(struct SwiftNetPacketMetadata) : 0)); \
        memcpy(buffer + GET_PREPEND_SIZE(network_data) + sizeof(struct ip) + offsetof(struct SwiftNetChunkMetadata, checksum), &checksum, sizeof(checksum)); \
        memcpy(buffer + GET_PREPEND_SIZE(network_data) + offsetof(struct ip, ip_sum), &ip_sum, SIZEOF_FIELD(struct ip, ip_sum)); \
        }

    #define GET_ADDR_TYPE(network_data) (network_data)->addr_type
    #define GET_PREPEND_SIZE(network_data) (network_data)->prepend_size

    #define HANDLE_PACKET_CONSTRUCTION(ip_header, chunk_metadata, packet_metadata, network_data, eth_hdr, buffer_size, buffer_name) \
        uint8_t buffer_name[buffer_size + (packet_metadata == NULL ? 0 : sizeof(struct SwiftNetPacketMetadata)) + PACKET_HEADER_SIZE + GET_PREPEND_SIZE(network_data)]; \
        if((network_data)->addr_type == DLT_NULL) { \
            uint32_t family = PF_INET; \
            memcpy(buffer_name, &family, sizeof(family)); \
            memcpy(buffer_name + sizeof(family), ip_header, sizeof(*ip_header)); \
            memcpy(buffer_name + sizeof(family) + sizeof(*ip_header), chunk_metadata, sizeof(*chunk_metadata)); \
            if(packet_metadata != NULL) memcpy(buffer_name + sizeof(family) + sizeof(*ip_header) + sizeof(*chunk_metadata), packet_metadata, sizeof(struct SwiftNetPacketMetadata)); \
        } else if((network_data)->addr_type == DLT_EN10MB){ \
            memcpy(buffer_name, eth_hdr, sizeof(*eth_hdr)); \
            memcpy(buffer_name + sizeof(*eth_hdr), ip_header, sizeof(*ip_header)); \
            memcpy(buffer_name + sizeof(*eth_hdr) + sizeof(*ip_header), chunk_metadata, sizeof(*chunk_metadata)); \
            if(packet_metadata != NULL) memcpy(buffer_name + sizeof(*eth_hdr) + sizeof(*ip_header) + sizeof(*chunk_metadata), packet_metadata, sizeof(struct SwiftNetPacketMetadata)); \
        }

    #define FREE_PACKET_CONSTRUCTION(buffer_name, network_data)

    extern void swiftnet_pcap_open(const char* const restrict interface, struct SwiftNetNetworkData* const network_data);
    extern int swiftnet_pcap_send(pcap_t *pcap, const uint8_t *data, const uint32_t len);

    inline static struct SwiftNetNetworkData swiftnet_initialize_networking(const char* const restrict interface) {
        struct SwiftNetNetworkData network_data;
        swiftnet_pcap_open(interface, &network_data);
        if (unlikely(network_data.pcap == NULL)) {
            PRINT_ERROR("Failed to open pcap");

            struct SwiftNetNetworkData net_data_null;
            memset(&net_data_null, 0x00, sizeof(net_data_null));

            return net_data_null;
        }

        const uint8_t addr_type = (uint8_t)pcap_datalink(network_data.pcap);
        
        network_data.addr_type = addr_type;
        network_data.prepend_size = PACKET_PREPEND_SIZE(addr_type);

        return network_data;
    }

    #define SWIFTNET_BREAK_RECEIVER_LOOP(network_data) \
        pcap_breakloop((network_data)->pcap)

    #define SWIFTNET_LOOP_PACKETS(network_data, listener) \
        pcap_loop((network_data)->pcap, 0, pcap_packet_handle, (void*)listener);

    #define SWIFTNET_CLOSE_CONNECTION(network_data) \
        pcap_close((network_data)->pcap); \
        pcap_freecode(&(network_data)->fp);

    #define SWIFTNET_SEND_PACKET(network_data, buffer, len, packet_metadata) \
	while(swiftnet_pcap_send((network_data)->pcap, buffer, len + GET_PREPEND_SIZE(network_data) + PACKET_HEADER_SIZE + (packet_metadata ? sizeof(struct SwiftNetPacketMetadata) : 0)) == -2) { \
        usleep(2000); \
    }

    #define SWIFTNET_SEND_INTERNAL_PACKET(network_data, buffer, len, packet_metadata) \
	while(swiftnet_pcap_send((network_data)->pcap, buffer, len + GET_PREPEND_SIZE(network_data) + PACKET_HEADER_SIZE + (packet_metadata ? sizeof(struct SwiftNetPacketMetadata) : 0)) == -2) { \
        usleep(2000); \
    }

#elif defined(SWIFT_NET_BACKEND_DPDK)
    #include <rte_ethdev.h>
    #include <rte_mbuf.h>

    #define WAIT_LISTENER_THREAD(listener) \
        rte_eal_wait_lcore((listener)->lcore);

    #define HANDLE_CHECKSUM(buffer, size, network_data, packet_metadata) \
        { \
            const uint32_t checksum = crc32(buffer + GET_PREPEND_SIZE(network_data) + sizeof(struct ip), size + sizeof(struct SwiftNetChunkMetadata) + (packet_metadata ? sizeof(struct SwiftNetPacketMetadata) : 0)); \
            memcpy(buffer + GET_PREPEND_SIZE(network_data) + sizeof(struct ip) + offsetof(struct SwiftNetChunkMetadata, checksum), &checksum, sizeof(checksum)); \
        }

    #define GET_ADDR_TYPE(network_data) (network_data)->addr_type
    #define GET_PREPEND_SIZE(network_data) (network_data)->prepend_size

    #define HANDLE_PACKET_CONSTRUCTION(ip_header, chunk_metadata, packet_metadata, network_data, eth_hdr, data_size, buffer_name) \
        const uint16_t buffer_name##buffer_size = data_size + (packet_metadata == NULL ? 0 : sizeof(struct SwiftNetPacketMetadata)) + PACKET_HEADER_SIZE + GET_PREPEND_SIZE(network_data); \
        struct rte_mbuf* buffer_name##_internal_mem_buf = rte_pktmbuf_alloc((network_data)->mem_pool); \
        if(unlikely(buffer_name##_internal_mem_buf == NULL)) { \
            PRINT_ERROR("Failed to alloc pktmbuf"); \
            exit(EXIT_FAILURE); \
        } \
        uint8_t* restrict const buffer_name = (uint8_t*)rte_pktmbuf_append(buffer_name##_internal_mem_buf, buffer_name##buffer_size); \
        ASSUME(buffer_name != NULL); \
        buffer_name##_internal_mem_buf->data_len = buffer_name##buffer_size; \
        buffer_name##_internal_mem_buf->pkt_len = buffer_name##buffer_size; \
        if((network_data)->addr_type == 0) { \
            memcpy(buffer_name, ip_header, sizeof(*ip_header)); \
            memcpy(buffer_name + sizeof(*ip_header), chunk_metadata, sizeof(*chunk_metadata)); \
            if(packet_metadata != NULL) memcpy(buffer_name + sizeof(*ip_header) + sizeof(*chunk_metadata), packet_metadata, sizeof(struct SwiftNetPacketMetadata)); \
        } else { \
            memcpy(buffer_name, eth_hdr, sizeof(*eth_hdr)); \
            memcpy(buffer_name + sizeof(*eth_hdr), ip_header, sizeof(*ip_header)); \
            memcpy(buffer_name + sizeof(*eth_hdr) + sizeof(*ip_header), chunk_metadata, sizeof(*chunk_metadata)); \
            if(packet_metadata != NULL) memcpy(buffer_name + sizeof(*eth_hdr) + sizeof(*ip_header) + sizeof(*chunk_metadata), packet_metadata, sizeof(struct SwiftNetPacketMetadata)); \
        }

    #define SWIFTNET_LOOP_PACKETS(network_data, listener) \
        while(atomic_load_explicit(&(network_data)->closing, memory_order_acquire) == false) { \
            struct rte_mbuf* buffers[DPDK_BURST_SIZE]; \
            uint16_t nb_rx = rte_eth_rx_burst((network_data)->port, 0, buffers, DPDK_BURST_SIZE); \
            if (likely(nb_rx > 0)) { \
                for (uint16_t i = 0; i < nb_rx; i++) { \
                    struct rte_mbuf* buffer = buffers[i]; \
                    uint8_t* const raw_data_ptr = rte_pktmbuf_mtod(buffer, uint8_t*); \
                    dpdk_packet_handle(listener, buffer, raw_data_ptr); \
                } \
            } else { \
                rte_pause(); \
            } \
        }

    #define FREE_PACKET_CONSTRUCTION(buffer_name, network_data) \
        rte_pktmbuf_free(buffer_name##_internal_mem_buf);

    #define SWIFTNET_BREAK_RECEIVER_LOOP(network_data) \
        atomic_store_explicit(&(network_data)->closing, true, memory_order_release);

    extern void swiftnet_dpdk_open_port(const uint16_t port, struct SwiftNetNetworkData* restrict const);
    extern int swiftnet_dpdk_send(const struct SwiftNetNetworkData* const network_data, struct rte_mbuf* buf);

    inline static struct SwiftNetNetworkData swiftnet_initialize_networking(const char* const restrict interface) {
        struct SwiftNetNetworkData network_data;
        uint16_t interface_port;
        int ret;

        ret = rte_eth_dev_get_port_by_name(interface, &interface_port);

        if(ret < 0) {
            PRINT_ERROR("Failed to get dpdk port id on interface: %s err = %d", interface, ret);
            exit(EXIT_FAILURE);
        }

        network_data = (struct SwiftNetNetworkData) {
            .port = interface_port,
            .addr_type = 1,
            .prepend_size = sizeof(struct ether_header)
        };

        swiftnet_dpdk_open_port(interface_port, &network_data);

        atomic_store_explicit(&network_data.closing, false, memory_order_release);

        return network_data;
    }


    #define SWIFTNET_CLOSE_CONNECTION(network_data) \
        rte_eth_dev_stop((network_data)->port); \
        rte_mempool_free((network_data)->mem_pool);

    #define SWIFTNET_SEND_INTERNAL_PACKET(network_data, buffer, len, packet_metadata) \
        swiftnet_dpdk_send((network_data), buffer##_internal_mem_buf);

    #define SWIFTNET_SEND_PACKET(network_data, buffer, len, packet_metadata) \
        swiftnet_dpdk_send((network_data), buffer);
#endif


#pragma once

#include "../swift_net.h"
#include "internal.h"
#include <stdint.h>
#include <string.h>

#ifdef SWIFTNET_BACKEND_PCAP

#include <pcap/pcap.h>
    // Simple crc16 call with proper memory order
    #define HANDLE_CHECKSUM(buffer, size, network_data) \
        const uint32_t checksum = crc32(buffer, size); \
        memcpy(buffer + (network_data)->prepend_size + sizeof(struct ip) + offsetof(struct SwiftNetPacketInfo, checksum), &checksum, sizeof(checksum));

    #define GET_ADDR_TYPE(network_data) (network_data)->addr_type
    #define GET_PREPEND_SIZE(network_data) (network_data)->prepend_size

    #define HANDLE_PACKET_CONSTRUCTION(ip_header, packet_info, network_data, eth_hdr, buffer_size, buffer_name) \
        uint8_t buffer_name[buffer_size]; \
        if((network_data)->addr_type == DLT_NULL) { \
            uint32_t family = PF_INET; \
            memcpy(buffer_name, &family, sizeof(family)); \
            memcpy(buffer_name + sizeof(family), ip_header, sizeof(*ip_header)); \
            memcpy(buffer_name + sizeof(family) + sizeof(*ip_header), packet_info, sizeof(*packet_info)); \
        } else if((network_data)->addr_type == DLT_EN10MB){ \
            memcpy(buffer_name, eth_hdr, sizeof(*eth_hdr)); \
            memcpy(buffer_name + sizeof(*eth_hdr), ip_header, sizeof(*ip_header)); \
            memcpy(buffer_name + sizeof(*eth_hdr) + sizeof(*ip_header), packet_info, sizeof(*packet_info)); \
        } \


    extern pcap_t* swiftnet_pcap_open(const char* const restrict interface);
    extern int swiftnet_pcap_send(pcap_t *pcap, const uint8_t *data, int len);

    inline static struct SwiftNetNetworkData swiftnet_initialize_networking(const char* const restrict interface) {
        pcap_t* pcap = swiftnet_pcap_open(interface);
        if (unlikely(pcap == NULL)) {
            struct SwiftNetNetworkData net_data_null;
            memset(&net_data_null, 0x00, sizeof(net_data_null));

            return net_data_null;
        }

        const uint8_t addr_type = pcap_datalink(pcap);
        
        struct SwiftNetNetworkData network_data = {
            .pcap = pcap,
            .addr_type = addr_type,
            .prepend_size = PACKET_PREPEND_SIZE(addr_type)
        };

        return network_data;
    }

    inline static void swiftnet_close_connection(struct SwiftNetNetworkData* restrict const network_data) {
        pcap_close(network_data->pcap);
    }

    #define SWIFTNET_BREAK_RECEIVER_LOOP(network_data) \
        pcap_breakloop((network_data)->pcap)

    #define SWIFTNET_LOOP_PACKETS(network_data, listener) \
        pcap_loop((network_data)->pcap, 0, pcap_packet_handle, (void*)listener)

    #define SWIFTNET_CLOSE_CONNECTION(network_data) \
        pcap_close((network_data)->pcap);

    #define SWIFTNET_SEND_PACKET(network_data, buffer, len) \
	while(swiftnet_pcap_send((network_data)->pcap, buffer, len) == -2) { \
        usleep(2000); \
    }
#elif SWIFTNET_PCAP_DPDK
// future backend functions
#endif

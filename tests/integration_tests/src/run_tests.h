#pragma once

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "../../shared.h"

struct TestSendingPacketArgs {
    const char* ip_address;
    const bool loopback;
    const uint32_t client_data_len;
    const uint32_t server_data_len;
};

struct TestMakingRequestArgs {
    const char* ip_address;
    const bool loopback;
    const enum ConnectionType receiver;
    const uint32_t request_data_len;
    const uint32_t response_data_len;
};

union Args {
    struct TestSendingPacketArgs test_sending_packet_args;
    struct TestMakingRequestArgs test_making_request_args;
};

struct Test {
    int (*function)(const union Args*);
    const union Args args;
    const char* test_name;
};

extern int test_sending_packet(const union Args* args_ptr);
extern int test_making_request(const union Args* args_ptr);

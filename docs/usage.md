# SwiftNet Usage

**You must run with sudo** (pcap raw access).

Call `swiftnet_initialize()` once at startup and `swiftnet_cleanup()` at shutdown.

## Initialize / Cleanup

```c
swiftnet_initialize();

// ... create connections, send, etc ...

swiftnet_cleanup();
```

## Create Server

```c
struct SwiftNetServer* server = swiftnet_create_server(8080, false /* loopback */);
if (server == NULL) {
    // failed to open interface etc.
}
```

- `loopback = true` uses the loopback interface (good for local tests).
- Server will start its own listener + processing threads.

## Create Client

```c
struct SwiftNetClientConnection* client = swiftnet_create_client("127.0.0.1", 8080, 1000 /* timeout ms */);
if (client == NULL) {
    // failed to reach server or complete initial handshake
}
```

Client performs a short handshake to learn the server's MTU.

## Message Handlers

```c
void on_client_packet(struct SwiftNetClientPacketData* packet, void* user) {
    // packet->metadata has data_length, packet_id, port_info, expecting_response (if requests enabled)
    uint8_t byte = *(uint8_t*)swiftnet_client_read_packet(packet, 1);

    swiftnet_client_destroy_packet_data(packet, client);
}

swiftnet_client_set_message_handler(client, on_client_packet, NULL /* user arg */);
```

Server side is identical but uses `struct SwiftNetServerPacketData*` and `swiftnet_server_set_message_handler`.

The handler is invoked (on a background thread) after the library has fully reassembled any chunked packet.

When sending from a server handler back to that client, use the address that came in:

```c
swiftnet_server_send_packet(server, &buf, packet->metadata.sender);
```

`metadata.sender` contains the address, port, mac, and MTU for that client.

## Packet Buffers

```c
struct SwiftNetPacketBuffer buf = swiftnet_create_packet_buffer(1024);

int32_t value = 42;
swiftnet_append_to_buffer(&value, sizeof(value), &buf);

// or write at an offset
swiftnet_write_packet_buffer(0, &buf, &value, sizeof(value));

swiftnet_client_send_packet(client, &buf);
swiftnet_destroy_packet_buffer(&buf);
```

Other helpers:
- `swiftnet_resize_packet_buffer(new_size, &buf)`
- `swiftnet_create_packet_buffer`, `swiftnet_destroy_packet_buffer`

## Sending

Client (to its server):

```c
swiftnet_client_send_packet(client, &buf);
```

Server (to a specific client):

```c
swiftnet_server_send_packet(server, &buf, target_addr_data);
```

The library handles splitting > MTU payloads into chunks and retransmitting lost ones automatically.

## Reading Received Packets

Inside your handler:

```c
void* data = swiftnet_client_read_packet(packet, packet->metadata.data_length);
// or read piecemeal:
uint8_t first = *(uint8_t*)swiftnet_client_read_packet(packet, 1);
```

Always call the destroy function when you are done with the packet data:

- `swiftnet_client_destroy_packet_data(packet, client_conn)`
- `swiftnet_server_destroy_packet_data(packet, server)`

## Requests / Responses (enabled unless SWIFT_NET_DISABLE_REQUESTS)

Synchronous request from client:

```c
struct SwiftNetPacketBuffer req_buf = swiftnet_create_packet_buffer(size);
swiftnet_append_to_buffer(data, size, &req_buf);

struct SwiftNetClientPacketData* reply = swiftnet_client_make_request(client, &req_buf, 1000 /* ms */);
if (reply) {
    // read from reply the same way
    swiftnet_client_destroy_packet_data(reply, client);
}
swiftnet_destroy_packet_buffer(&req_buf);
```

Server can also send requests to clients using `swiftnet_server_make_request(server, &buf, client_addr, timeout)`.

In a handler, if `packet->metadata.expecting_response` is true you can reply without the caller blocking on a new make_request:

```c
swiftnet_client_make_response(client, packet, &response_buf);
```

Same pattern exists for server.

## Debug Output (enabled unless SWIFT_NET_DISABLE_DEBUGGING)

```c
swiftnet_add_debug_flags(SWIFTNET_DEBUG_FLAGS(
    SWIFTNET_DEBUG_PACKETS_SENDING |
    SWIFTNET_DEBUG_PACKETS_RECEIVING |
    SWIFTNET_DEBUG_INITIALIZATION |
    SWIFTNET_DEBUG_LOST_PACKETS
));
```

Remove flags with `swiftnet_remove_debug_flags(...)`.

## Important Notes

- Always run the binary as root / with sudo.
- The library owns several background threads per connection (listener, packet processor, callback executor).
- Cleanup functions stop threads and free the allocators / hashmaps used by that connection.
- All the heavy lifting (reassembly, lost packet recovery, checksums) happens inside the library.

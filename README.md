# SwiftNet - Networking Library

## SwiftNet is a lightweight networking library built on top of pcap, operating at Layer 2. It is designed for developers who value simplicity, readability, and performance. It handles chunked delivery for large payloads, automatic lost-chunk recovery, callback handlers, and has an optional request/response model. Call swiftnet_initialize() before creating clients or servers.

- [Features](#features)
- [Installation](#installation)
- [Future Version Goals](#future-version-goals)
- [Example](#example)
- [Syntax](#syntax)
- [Contributing](#contributing)
- [Goals](#goals)
- [License](#license)
- [Performance](#performance)
- [Use Cases](#use-cases)

## Use Cases
- Multiplayer game networking
- Applications requiring a very simple API while delivering solid performance
- Future-proof software with maximum server-side performance

## Supported Platforms
- **Apple Silicon (macOS arm64)**
- **Linux arm64** (Release build works, but testing is disabled due to TSAN issues)

## Features
- **💡 Ease of Use**: Simple API designed to get up and running quickly, without needing to deal directly with sockets, ip/eth headers or complicated libraries.
- **📂 Lightweight**: No dependencies except PCAP and a small footprint.

## Why Use SwiftNet?
- **Straightforward API:** Get up and running with minimal setup.
- **Open Source and Collaborative:** Contributions are welcome to make it even better.
- **Compile time feature choosing** Compile only specific features of the library.
- **Lightweight** Static library build is under 1MB.
- **Future-proof** Designed to scale with optional features enabled at compile time.
- **Server side performance** The main focus is to make linux servers easily scalable, by enabling AF DXP, DPDK or other ways of accelerating packets without operating system involvement.

## Future Version Goals
- **0.5.0:** Performance improvements in critical paths, ready for some real world usage

## Goals

### Upcoming goals
- Optimize the most obvious parts of the codebase
- Stabilize the API to avoid breaking changes in future releases
- AF_XDP Linux support

- Long-term: optional hardware acceleration (FPGA/ASIC) with external NIC to bypass OS overhead for server side processing

## Performance

- **Test Overview**
  One large packet with 100 Million bytes of data

- **Hardware & Conditions**  
  Tested on a MacBook Air M3 (my daily driver machine, running multiple background applications)

- **Interface**  
  Real Wi-Fi interface: en0

- **Throughput**  
  20.9 MB/s

- **Memory Usage**  
  **Peak memory footprint: 203 million bytes**
  - 100M bytes are used for buffers on receiver and sender
  - 3M bytes are used on internal data
  

- **CPU Usage**  
  Average utilization: ~9%

- **Detailed Timing (from /usr/bin/time -l)**  
  - Real (wall-clock) time: 4.78 seconds  
  - User CPU time: 0.07 seconds  
  - System CPU time: 0.31 seconds  
  - Total CPU time: 0.38 seconds

- **CPU Cycles**  
  1 513 423 854 cycles

## Installation
Follow these steps to install SwiftNet:

## VCPKG
```
vcpkg install morcules-swiftnet
```

## From Source
1. Clone the repository to your local machine:
```bash
git clone https://github.com/morcules/SwiftNet
```
2. Navigate to the build directory inside the SwiftNet directory:
```bash
cd SwiftNet/build
```
3. Compile:
```bash
./build_for_release.sh
```
4. To use SwiftNet in your project:
- Include `swift_net.h` in your main source file (e.g., `main.c`).
- Link against the static library `libswiftnet.a` using your compiler.

## Important note
- To run the library successfully, you're required to run the app with sudo.
- Pcap requires sudo

## Example
```
swiftnet_initialize();

struct SwiftNetClientConnection* const client_conn = swiftnet_create_client("127.0.0.1", 8080, 1000);
if (client_conn == NULL) {
    printf("Failed to create client connection\n");
    return -1;
}

swiftnet_client_set_message_handler(client_conn, on_client_packet, NULL);

struct SwiftNetPacketBuffer buf = swiftnet_create_packet_buffer(1024);

int code = 0xFF;
swiftnet_append_to_buffer(&code, sizeof(code), &buf);

swiftnet_client_send_packet(client_conn, &buf);
swiftnet_destroy_packet_buffer(&buf);

/* later */
swiftnet_client_cleanup(client_conn);
swiftnet_cleanup();
```

Handlers get called with `struct SwiftNetClientPacketData*` (or the server equivalent). Use `swiftnet_client_read_packet` to pull data out, then `swiftnet_client_destroy_packet_data`. Server side is symmetric. Requests/responses are available when `SWIFT_NET_REQUESTS` is enabled.

## Syntax

- Every stack var has to be declared on top for easier variable clarity.
- New scopes can declare at top of the scope.
- Use gotos and labels for labeled progression.
- Trying to avoid many scopes in one function.

(only some files have the new style i'm working on it)

## Contributing

Contributions are very welcome no matter how small. Every single PR, issue, question, or typo fix is admired and appreciated.

- **Check out open issues** — Start with those labeled [`good first issue`](https://github.com/morcules/SwiftNet/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) or [`help wanted`](https://github.com/morcules/SwiftNet/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22).
- **Found a bug or have a feature idea?** Open an issue to discuss it first (especially for larger changes).
- **Want to fix something yourself?** Fork the repo, create a branch, and submit a pull request.

### Rules
- **AI** - You're free to use anything you want to your advantage, but AI written slop that wasn't even ran locally won't be merged. If you don't understand the code please do not subbmit anything.

## License
This project is licensed under the Apache License 2.0

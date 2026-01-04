# SwiftNet - Networking Library

## SwiftNet is a simple and easy to use networking library built using pcap working on ip layer 2. It is designed for developers who value simplicity, readability, and good performance.

- [Features](#features)
- [Installation](#installation)
- [Example](#example)
- [Contributing](#contributing)
- [Goals](#goals)
- [License](#license)

## Supported Platforms
- **Apple Silicon (macOS arm64)**
- **Linux arm64**

## Features
- **💡 Ease of Use**: Simple API designed to get up and running quickly, without needing to deal directly with raw sockets.
- **📂 Lightweight**: No dependencies except PCAP and a small footprint.

## Why Use SwiftNet?
- **Straightforward API:** Get up and running with minimal setup.
- **Open Source and Collaborative:** Contributions are welcome to make it even better.
- **Compile time feature choosing** Compile only specific features of the library.

## Goals

### Upcoming goals
- Switch from pcap to raw BPF
- Add performance benchmarks
- Optimize the most obvious parts of the codebase
- Stabilize the API to avoid breaking changes in future releases

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
- Include the SwiftNet.h header from the `src` directory in your main source file (e.g., `main.c`).
- Link against the static library `libswiftnet.a` using your compiler.

## Important note
- To run the library successfully, you're required to run the app with sudo.
- Pcap requires sudo

## Example
```
struct SwiftNetClientConnection* const client_conn = swiftnet_create_client(args.ip_address, 8080, 1000);
if (client_conn == NULL) {
    printf("Failed to create client connection\n");
    return -1;
}

swiftnet_client_set_message_handler(client_conn, on_client_packet, NULL);

struct SwiftNetPacketBuffer buf = swiftnet_client_create_packet_buffer(sizeof(int));

int code = 0xFF;

swiftnet_client_append_to_packet(&code, sizeof(code), &buf);
swiftnet_client_send_packet(client_conn, &buf);
swiftnet_client_destroy_packet_buffer(&buf);
```

## Contributing

Contributions are very welcome no matter how small. Every single PR, issue, question, or typo fix is admired and appreciated.

- **Check out open issues** — Start with those labeled [`good first issue`](https://github.com/morcules/SwiftNet/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) or [`help wanted`](https://github.com/morcules/SwiftNet/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22).
- **Found a bug or have a feature idea?** Open an issue to discuss it first (especially for larger changes).
- **Want to fix something yourself?** Fork the repo, create a branch, and submit a pull request.

## License
This project is licensed under the Apache License 2.0

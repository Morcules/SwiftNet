# SwiftNet - Networking Library

### SwiftNet is a simple and easy-to-use networking library built using pcap. It is designed for developers who value simplicity, readability, and good performance.

## This library focuses on functionality over speed for now. If you need high performance for a release, consider waiting. We plan to optimize performance once the library is stable and feature-complete.

## If you intend to use this library, please note that it has not been fully tested for public packet transmissions and will probably not work. These early versions are mainly for local testing and development.

## Supported Platforms
- **Apple Silicon (macOS arm64)**
- **Linux arm64**

## Features
- **💡 Ease of Use**: Simple API designed to get up and running quickly, without needing to deal directly with raw sockets.
- **📂 Lightweight**: No dependencies and a small footprint.

## Why Use SwiftNet?
- **Straightforward API:** Get up and running with minimal setup.
- **Open Source and Collaborative:** Contributions are welcome to make it even better.

## Installation
Follow these steps to install SwiftNet:

## VCPKG
```
vcpkg install morcules-swiftnet
```

## From Source
1. Clone the repository to your local machine:
```bash
git clone https://github.com/deadlightreal/SwiftNet
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

## License
This project is licensed under the Apache License 2.0

## Contact
For any questions or support, feel free to open an issue or contact me at [https://t.me/deadlightreal].

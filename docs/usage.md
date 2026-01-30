# OUTDATED!!!!!!!!

# Explanation of every single function

## SWIFT_NET_SERVER AND SWIFT_NET_CLIENT
### Usage:
- Sets the current thread to operate in either client or server mode. The library then executes different functions depending on the selected mode.

- When the thread is set to SWIFT_NET_SERVER, the system will handle incoming connections and process server-side functionality.
- When the thread is set to SWIFT_NET_CLIENT, the system will connect to a server and execute client-side operations.
- This allows you to easily switch between server and client behavior within the same application, depending on the configuration.

## InitializeSwiftNet
### Usage:
- Initializes the Swift Net library.
- **Note:** As of now, this function does not perform any actions, but it may be used in the future for setting up configurations or performing initialization tasks related to networking.

# SwiftNetSetBufferSize
### Arguments:
1. unsigned int - New Buffer Size: Specifies the desired size of the packet buffer.
2. Pointer to either SwiftNetClientConnection or SwiftNetServer: A pointer to the appropriate connection object (either client or server). The function will terminate if a null pointer is provided.
### Usage:
- Changes the packet buffer size to the specified new size.

# SwiftNetCreateClient
### Arguments:
1. char* - IP address of the server: The server's IP address to which the client will connect.
2. uint16_t - Port of the server: The port number on which the server is listening for connections.
### Usage:
- Establishes a client connection to the specified server at the given IP address and port. This function initiates the process of connecting the client to the server.
### Return:
- Pointer to SwiftNetClientConnection: Returns a pointer to the client connection struct that represents the established connection to the server.

# SwiftNetCreateServer
### Arguments:
1. char* - IP address of the server: The server's IP address to bind the server to.
2. uint16_t - Port of the server: The port number on which the server will listen for incoming client connections.
### Usage:
- Creates and initializes a server on the specified IP address and port. This function binds the server to the provided IP address and port, enabling it to accept incoming client connections on that address. The server will start listening for connections and handle requests accordingly.
### Return:
- Pointer to SwiftNetServer: Returns a pointer to the server struct that represents the server.

# SwiftNetSetMessageHandler
### Arguments:
1. void(uint8_t* data) - A function pointer to the handler function that will be called when a new packet is received. The handler function should accept a single argument: a uint8_t* (pointer to data), which represents the data sent with the packet.
2. Pointer to either SwiftNetClientConnection or SwiftNetServer: A pointer to the appropriate connection object (either client or server).
### Usage:
- Registers a callback function (handler) to handle incoming packet data. When a new packet is received, the specified handler function is called with the packet data as its argument.

# SwiftNetAppendToPacket
### Arguments:
1. Pointer to either SwiftNetClientConnection or SwiftNetServer: A pointer to the appropriate connection object (either client or server).
2. void* - Pointer to the data: The data that will be appended to the packet buffer.
3. unsigned int - Size in bytes of the data: The size of the data to be appended, in bytes.
### Usage:
- Appends the provided data to the current packet buffer for the specified connection and then increments the internal pointer to the next available space in the buffer.

# SwiftNetSendPacket
### Arguments:
1. Pointer to either SwiftNetClientConnection or SwiftNetServer: A pointer to the appropriate connection object (either client or server).
2. ClientAddress* (only necessary in SERVER mode, otherwise set it to NULL): The address of the client to which the packet should be sent. This argument is only required when the mode is set to SERVER, as the server may need to send a packet to a specific client. If using CLIENT mode, this should be set to NULL.
### Usage:
- Sends the constructed packet to the specified destination. In SERVER mode, the packet is sent to the provided client's address, while in CLIENT mode, the packet is sent to the connected server.

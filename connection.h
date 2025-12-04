#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <cstdint>

#define BITCOIN_PORT 8333
#define BITCOIN_TEST_PORT 18333
#define MAINNET_MAGIC 0xD9B4BEF9
#define PROTOCOL_VERSION 70015

// Resolve a DNS seed and return all found IPv4 peers as strings
std::vector<std::string> lookup_dns_seed(const char *seed);
// Connect to a peer; returns SOCKET or INVALID_SOCKET on failure
SOCKET connect_to_peer(const std::string &ip, int port);
// Helpers for little-endian encoding
void write_uint32_le(uint8_t* buf, uint32_t val);
void write_uint64_le(uint8_t* buf, uint64_t val);
// Send Bitcoin message with header
bool send_message(SOCKET sock, const std::string &command, uint8_t* payload, uint32_t len);
// Build minimal version payload
int build_version_payload(uint8_t* buf, const std::string &peer_ip);
// receive data from socket with timeout and error handling. Returns number of bytes received, or -1 on error/timeout
std::string recv_with_timeout(SOCKET sock, uint8_t* buffer, int buffer_size, const char* message_name);

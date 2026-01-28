#ifndef CONNECTION_H
#define CONNECTION_H

#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <cstdint>
#include <ctime>
#include <algorithm>

#define BITCOIN_PORT 8333
#define BITCOIN_TEST_PORT 18333

#define MAINNET_MAGIC 0xD9B4BEF9
#define PROTOCOL_VERSION 70015

// Typy inwentarza dla Bitcoina (potrzebne do funkcji inv/getdata)
enum InventoryType {
    MSG_ERROR = 0,
    MSG_TX = 1,
    MSG_BLOCK = 2,
    MSG_FILTERED_BLOCK = 3,
    MSG_CMPCT_BLOCK = 4
};


// Resolve a DNS seed and return all found IPv4 peers as strings
std::vector<std::string> lookup_dns_seed(const char *seed);
// Connect to a peer; returns SOCKET or INVALID_SOCKET on failure
SOCKET connect_to_peer(const std::string &ip, int port);
// Helpers for little-endian encoding
void write_uint32_le(uint8_t* buf, uint32_t val);
void write_uint64_le(uint8_t* buf, uint64_t val);

// Helper for converting hex strings to byte arrays (new)
void hex_string_to_bytes(const std::string& hex, uint8_t* out);

int64_t read_varint(const uint8_t* data, size_t len, size_t& offset);
// Send Bitcoin message with header
bool send_message(SOCKET sock, const std::string &command, uint8_t* payload, uint32_t len);
// Request peer address list (getaddr)
bool send_getaddr(SOCKET sock);
// Parse addr payload (Bitcoin P2P addr message) and print (IP:port list) for first 10 peers found
// Returns vector of (IP, port) pairs
std::vector<std::pair<std::string, int>> print_addr_list(const std::string& payload);
// Build minimal version payload
int build_version_payload(uint8_t* buf, const std::string &peer_ip);
// receive data from socket with timeout and error handling. Returns number of bytes received, or -1 on error/timeout
std::string recv_with_timeout(SOCKET sock, uint8_t* buffer, int buffer_size, const char* message_name);

// Helper for converting hex strings (like block hashes) to byte arrays
void hex_string_to_bytes(const std::string& hex, uint8_t* out);

// Sends a 'ping' message with a random nonce to keep the connection alive.
bool send_ping(SOCKET sock);

// Sends an 'alert' message. 
bool send_alert(SOCKET sock, const std::string& alert_message);

// Sends a 'reject' message to report a protocol error (CCode) to the peer.
// ccode: 0x01=Malformed, 0x10=Invalid, 0x40=Obsolete, etc.
bool send_reject(SOCKET sock, const std::string& rejected_command, uint8_t ccode, const std::string& reason);

// Sends a custom 'message' message for diagnostics.
bool send_diagnostic_message(SOCKET sock, const std::string& diagnostic_info);

// Sends a 'getheaders' message to request block headers from the peer.
bool send_getheaders(SOCKET sock);

// Block Inventory & Exchange
bool send_getheaders(SOCKET sock, const std::string& start_hash_hex);
bool send_getblocks(SOCKET sock, const std::string& start_hash_hex);
bool send_inv(SOCKET sock, InventoryType type, const std::string& hash_hex);
bool send_getdata(SOCKET sock, InventoryType type, const std::string& hash_hex);
bool send_tx(SOCKET sock, const std::vector<uint8_t>& raw_tx);
bool send_block(SOCKET sock, const std::vector<uint8_t>& raw_block);
bool send_headers(SOCKET sock, const std::vector<uint8_t>& raw_headers, uint64_t count);

#endif

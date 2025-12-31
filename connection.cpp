#include "connection.h"

// Resolve a DNS seed and return all found IPv4 peers as strings
std::vector<std::string> lookup_dns_seed(const char *seed)
{
    struct addrinfo hints, *result, *ptr;
    char current_ip[INET_ADDRSTRLEN];
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::cout << "Querying DNS seed: " << seed << '\n';
    int res = getaddrinfo(seed, std::to_string(BITCOIN_PORT).c_str(), &hints, &result);
    if (res != 0) {
        std::cout << "DNS lookup failed: " << res << '\n';
        return {};
    }
    std::vector<std::string> peers;
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        struct sockaddr_in *sockaddr_ipv4 = (struct sockaddr_in *)ptr->ai_addr;
        inet_ntop(AF_INET, &(sockaddr_ipv4->sin_addr), current_ip, sizeof(current_ip));
        std::cout << "Found peer: " << current_ip << ":" << BITCOIN_PORT << '\n';
        peers.emplace_back(current_ip);
    }
    freeaddrinfo(result);
    return peers;
}

// Connect to a peer; returns SOCKET or INVALID_SOCKET on failure
SOCKET connect_to_peer(const std::string &ip, int port) {
    // Detect if IPv6 by checking for colons in the address
    bool is_ipv6 = (ip.find(':') != std::string::npos);
    // Create socket with appropriate family
    SOCKET sock = socket(is_ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cout << "Socket creation failed: " << WSAGetLastError() << '\n';
        return INVALID_SOCKET;
    }
    std::cout << "Connecting to " << ip << ':' << port << " ..." << '\n';
    if (is_ipv6) {
        // IPv6
        struct sockaddr_in6 peer_addr = {0};
        peer_addr.sin6_family = AF_INET6;
        peer_addr.sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip.c_str(), &peer_addr.sin6_addr) != 1) {
            std::cout << "Invalid IPv6 address: " << ip << '\n';
            closesocket(sock);
            return INVALID_SOCKET;
        }

        if (connect(sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) == SOCKET_ERROR) {
            std::cout << "Connect failed: " << WSAGetLastError() << '\n';
            closesocket(sock);
            return INVALID_SOCKET;
        }
    } else {
        // IPv4
        struct sockaddr_in peer_addr = {0};
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons(port);
        if (inet_pton(AF_INET, ip.c_str(), &peer_addr.sin_addr) != 1) {
            std::cout << "Invalid IPv4 address: " << ip << '\n';
            closesocket(sock);
            return INVALID_SOCKET;
        }

        if (connect(sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) == SOCKET_ERROR) {
            std::cout << "Connect failed: " << WSAGetLastError() << '\n';
            closesocket(sock);
            return INVALID_SOCKET;
        }
    }
    std::cout << "Connected to " << ip << ':' << port << '\n';
    return sock;
}

// Send getaddr (no payload) to request peer address list
bool send_getaddr(SOCKET sock) {
    std::cout << "Sending GETADDR..." << std::endl;
    return send_message(sock, "getaddr", nullptr, 0);
}

// Parse addr payload (Bitcoin P2P addr message) and print (IP:port list) for first 10 peers found - returns vector of (IP, port) pairs
std::vector<std::pair<std::string, int>> print_addr_list(const std::string& payload) {
    std::vector<std::pair<std::string, int>> peers;
    const uint8_t* data = (const uint8_t*)payload.data();
    size_t len = payload.size();
    size_t offset = 0;
    int64_t count = read_varint(data, len, offset);
    if (count < 0) {
        std::cerr << "addr parse error: bad varint" << '\n';
        return peers;
    }
    std::cout << "Peers addr entries (" << count << ", showing first 10):" << '\n';
    int64_t display_limit = (count > 10) ? 10 : count;
    for (int64_t i = 0; i < count; i++) {
        if (offset + 30 > len) { break; }
        // skip timestamp (4) and services (8)
        offset += 4 + 8;
        const uint8_t* ip = data + offset; // 16 bytes
        offset += 16;
        uint16_t port = (data[offset] << 8) | data[offset+1];
        offset += 2;
        std::string ipstr;
        // handle IPv4-mapped IPv6: 10 zero bytes, 0xFF 0xFF, then 4 bytes IPv4
        bool is_v4_mapped = true;
        for (int j=0;j<10;j++) if (ip[j] != 0x00) { is_v4_mapped = false; break; }
        if (!(ip[10]==0xFF && ip[11]==0xFF)) is_v4_mapped = false;
        if (is_v4_mapped) {
            char buf[32];
            snprintf(buf, sizeof(buf), "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]);
            ipstr = buf;
        } else {
            // basic IPv6 print
            char buf[64];
            snprintf(buf, sizeof(buf), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                ip[0],ip[1],ip[2],ip[3],ip[4],ip[5],ip[6],ip[7],ip[8],ip[9],ip[10],ip[11],ip[12],ip[13],ip[14],ip[15]);
            ipstr = buf;
        }
        peers.push_back({ipstr, port});
        if (i < display_limit) {
            std::cout << (i+1) << ") " << ipstr << ":" << port << '\n';
        }
    }
    if (count > 10) {
        std::cout << "... and " << (count - 10) << " more peers\n";
    }
    return peers;
}


// Helpers for little-endian encoding
void write_uint32_le(uint8_t* buf, uint32_t val) {
    buf[0] = val & 0xFF; buf[1] = (val >> 8) & 0xFF;
    buf[2] = (val >> 16) & 0xFF; buf[3] = (val >> 24) & 0xFF;
}
void write_uint64_le(uint8_t* buf, uint64_t val) {
    for (int i = 0; i < 8; i++) buf[i] = (val >> (8*i)) & 0xFF;
}

// Print hex dump of data for testing only!
void hex_dump(const uint8_t* data, int len, const char* label = "") {
    if (label[0] != '\0') std::cout << label << ": ";
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

// Compute double SHA256 checksum of payload (first 4 bytes of hash)
void compute_checksum(uint8_t* payload, uint32_t len, uint8_t* checksum_out) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed\n";
        memset(checksum_out, 0, 4);
        return;
    }
    
    // First SHA256 hash
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash failed\n";
        CryptReleaseContext(hProv, 0);
        memset(checksum_out, 0, 4);
        return;
    }
    
    if (!CryptHashData(hHash, payload, len, 0)) {
        std::cerr << "CryptHashData failed\n";
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        memset(checksum_out, 0, 4);
        return;
    }
    
    uint8_t hash1[32];
    DWORD hash_len = 32;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash1, &hash_len, 0)) {
        std::cerr << "CryptGetHashParam failed\n";
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        memset(checksum_out, 0, 4);
        return;
    }
    CryptDestroyHash(hHash);
    
    // Second SHA256 hash
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash (2nd) failed\n";
        CryptReleaseContext(hProv, 0);
        memset(checksum_out, 0, 4);
        return;
    }
    
    if (!CryptHashData(hHash, hash1, 32, 0)) {
        std::cerr << "CryptHashData (2nd) failed\n";
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        memset(checksum_out, 0, 4);
        return;
    }
    
    uint8_t hash2[32];
    hash_len = 32;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash2, &hash_len, 0)) {
        std::cerr << "CryptGetHashParam (2nd) failed\n";
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        memset(checksum_out, 0, 4);
        return;
    }
    
    // Return first 4 bytes of double hash
    memcpy(checksum_out, hash2, 4);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}

// Send Bitcoin message with header
bool send_message(SOCKET sock, const std::string &command, uint8_t* payload, uint32_t len) {
    uint8_t header[24] = {0};
    write_uint32_le(header, MAINNET_MAGIC);
    for (size_t i = 0; i < 12 && i < command.size(); i++) header[4+i] = command[i];
    write_uint32_le(header+16, len);
    
    // Compute checksum: double SHA256 of payload
    uint8_t checksum[4];
    compute_checksum(payload, len, checksum);
    memcpy(header+20, checksum, 4);
    std::cout << "Sending header for command: " << command << std::endl;
    if (send(sock, (char*)header, 24, 0) == SOCKET_ERROR) {
        std::cerr << "Failed to send header: " << WSAGetLastError() << '\n';
        return false;
    }
    if (len > 0 && send(sock, (char*)payload, len, 0) == SOCKET_ERROR) {
        std::cerr << "Failed to send payload: " << WSAGetLastError() << '\n';
        return false;
    }
    std::cout << command << " sent successfully" << std::endl;
    return true;
}

// Build minimal version payload
int build_version_payload(uint8_t* buf, const std::string &peer_ip) {
    int offset = 0;
    // 4 bytes: version
    write_uint32_le(buf+offset, PROTOCOL_VERSION); offset+=4;
    // 8 bytes: services
    write_uint64_le(buf+offset, 0); offset+=8;
    // 8 bytes: timestamp
    write_uint64_le(buf+offset, (int64_t)time(nullptr)); offset+=8;
    // 26 bytes: addr_recv (IPv4-mapped IPv6) - peer address
    memset(buf+offset, 0, 26);
    buf[offset+10] = 0xff; buf[offset+11] = 0xff;
    // Parse peer IP and write it
    uint8_t ip_bytes[4];
    sscanf(peer_ip.c_str(), "%hhu.%hhu.%hhu.%hhu", &ip_bytes[0], &ip_bytes[1], &ip_bytes[2], &ip_bytes[3]);
    buf[offset+12] = ip_bytes[0]; buf[offset+13] = ip_bytes[1]; buf[offset+14] = ip_bytes[2]; buf[offset+15] = ip_bytes[3];
    buf[offset+16] = (BITCOIN_PORT >> 8) & 0xFF; buf[offset+17] = BITCOIN_PORT & 0xFF;
    offset += 26;
    // 26 bytes: addr_from (your IP) - use a placeholder like 192.168.0.1
    memset(buf+offset, 0, 26);
    buf[offset+10] = 0xff; buf[offset+11] = 0xff;
    buf[offset+12] = 192; buf[offset+13] = 168; buf[offset+14] = 0; buf[offset+15] = 1; // placeholder: 192.168.0.1
    buf[offset+16] = (BITCOIN_PORT >> 8) & 0xFF; buf[offset+17] = BITCOIN_PORT & 0xFF;
    offset += 26;
    // 8 bytes: nonce
    write_uint64_le(buf+offset, ((uint64_t)rand()<<32)|rand()); offset+=8;
    // 1 byte: user agent length = 0
    buf[offset++] = 0;
    // 4 bytes: start_height = 0
    write_uint32_le(buf+offset, 0); offset+=4;
    // 1 byte: relay flag = 0
    buf[offset++] = 0;
    return offset;
}

// receive data from socket with timeout and error handling
// Returns number of bytes received, or -1 on error/timeout
std::string recv_with_timeout(SOCKET sock, uint8_t* buffer, int buffer_size, const char* message_name)
{
    int len = recv(sock, (char*)buffer, buffer_size, 0);
    if (len == SOCKET_ERROR)
    {
        int err = WSAGetLastError();
        if (err == WSAETIMEDOUT)
            std::cerr << "Recv timeout: peer did not respond (waiting for " << message_name << ")\n";
        else
            std::cerr << "Recv error: " << err << '\n';
        return "-1";
    }
    else if (len == 0)
    {
        std::cerr << "Peer closed connection\n";
        return "-1";
    }
    std::cout << "Received " << len << " bytes (" << message_name << ").\n";
    return std::string((char*)buffer, len);
}

// --- ADDED IMPLEMENTATIONS ---

// Helper: Append a Variable Length Integer (VarInt) to the buffer
// Bitcoin protocol uses VarInt to save space for integer values.
void write_varint(std::vector<uint8_t>& buf, uint64_t val) {
    if (val < 0xfd) {
        buf.push_back((uint8_t)val);
    }
    else if (val <= 0xffff) {
        buf.push_back(0xfd);
        buf.push_back((uint8_t)(val & 0xFF));
        buf.push_back((uint8_t)((val >> 8) & 0xFF));
    }
    else if (val <= 0xffffffff) {
        buf.push_back(0xfe);
        for (int i = 0; i < 4; i++) buf.push_back((uint8_t)((val >> (8 * i)) & 0xFF));
    }
    else {
        buf.push_back(0xff);
        for (int i = 0; i < 8; i++) buf.push_back((uint8_t)((val >> (8 * i)) & 0xFF));
    }
}

// Helper: Append a Variable Length String (VarStr) to the buffer
void write_varstr(std::vector<uint8_t>& buf, const std::string& s) {
    write_varint(buf, s.size());
    buf.insert(buf.end(), s.begin(), s.end());
}

// Helper: read VarInt from buffer at offset; returns value and advances offset; -1 on error
int64_t read_varint(const uint8_t* data, size_t len, size_t& offset) {
    if (offset >= len) return -1;
    uint8_t prefix = data[offset++];
    if (prefix < 0xfd) return prefix;
    if (prefix == 0xfd) {
        if (offset + 2 > len) return -1;
        uint16_t v = data[offset] | (data[offset+1] << 8);
        offset += 2;
        return v;
    }
    if (prefix == 0xfe) {
        if (offset + 4 > len) return -1;
        uint32_t v = 0;
        for (int i=0;i<4;i++) v |= (uint32_t)data[offset+i] << (8*i);
        offset += 4;
        return v;
    }
    // 0xff
    if (offset + 8 > len) return -1;
    uint64_t v = 0;
    for (int i=0;i<8;i++) v |= (uint64_t)data[offset+i] << (8*i);
    offset += 8;
    return (int64_t)v;
}

// Helper: Convert hex string to byte array (reversing for little-endian if needed for hashes)
void hex_string_to_bytes(const std::string& hex, uint8_t* out) {
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        // Bitcoin hashes are internal byte order (often reversed), here we reverse to match wire format
        out[31 - (i / 2)] = byte;
    }
}

// 1. PING MESSAGE
bool send_ping(SOCKET sock) {
    uint64_t nonce = ((uint64_t)rand() << 32) | rand();
    uint8_t payload[8];
    write_uint64_le(payload, nonce);

    std::cout << "Sending PING (nonce=" << nonce << ")...\n";
    return send_message(sock, "ping", payload, 8);
}

// 2. ALERT MESSAGE
// Note: This constructs a simplified payload. A real alert requires a signature 
// from a specific key that is no longer in use, but the structure is valid.
bool send_alert(SOCKET sock, const std::string& alert_message) {
    std::vector<uint8_t> payload;

    // The alert payload is actually a serialized data structure + signature.
    // For this assignment, we construct a dummy serialized alert content.
    std::vector<uint8_t> alert_content;

    // Version (int32)
    uint8_t tmp4[4];
    write_uint32_le(tmp4, 1); alert_content.insert(alert_content.end(), tmp4, tmp4 + 4);
    // Relay Until (int64) - timestamp
    uint8_t tmp8[8];
    write_uint64_le(tmp8, (uint64_t)time(nullptr) + 3600); alert_content.insert(alert_content.end(), tmp8, tmp8 + 8);
    // Expiration (int64)
    write_uint64_le(tmp8, (uint64_t)time(nullptr) + 7200); alert_content.insert(alert_content.end(), tmp8, tmp8 + 8);
    // ID (int32)
    write_uint32_le(tmp4, 1001); alert_content.insert(alert_content.end(), tmp4, tmp4 + 4);
    // Cancel (int32)
    write_uint32_le(tmp4, 0); alert_content.insert(alert_content.end(), tmp4, tmp4 + 4);
    // SetCancel (set<int32>) - 0 items? No, SetCancel is internal. Let's assume empty set:
    // Actually, constructing the full variable payload is complex. 
    // We will simulate the variable parts:
    write_varint(alert_content, 0); // 0 cancellations
    write_uint32_le(tmp4, 0); alert_content.insert(alert_content.end(), tmp4, tmp4 + 4); // MinVer
    write_uint32_le(tmp4, PROTOCOL_VERSION); alert_content.insert(alert_content.end(), tmp4, tmp4 + 4); // MaxVer
    write_varint(alert_content, 0); // 0 subvers
    write_uint32_le(tmp4, 1); alert_content.insert(alert_content.end(), tmp4, tmp4 + 4); // Priority
    write_varstr(alert_content, alert_message); // Comment
    write_varstr(alert_content, "BitLab Alert"); // StatusBar
    write_varstr(alert_content, ""); // Reserved

    // Now pack the final payload: [VarStr Alert] [VarStr Signature]
    write_varstr(payload, std::string(alert_content.begin(), alert_content.end()));
    write_varstr(payload, ""); // Empty signature (invalid, but correct structure)

    std::cout << "Sending ALERT: " << alert_message << "\n";
    return send_message(sock, "alert", payload.data(), payload.size());
}

// 3. REJECT MESSAGE
bool send_reject(SOCKET sock, const std::string& rejected_command, uint8_t ccode, const std::string& reason) {
    std::vector<uint8_t> payload;

    // 1. message (VarStr): type of message rejected
    write_varstr(payload, rejected_command);

    // 2. ccode (1 byte): code relating to rejected message
    // 0x01: MALFORMED, 0x10: INVALID, 0x11: OBSOLETE, 0x12: DUPLICATE, 0x40: NONSTANDARD
    payload.push_back(ccode);

    // 3. reason (VarStr): text version of reason for rejection
    write_varstr(payload, reason);

    // 4. data (optional): ignored here for simplicity

    std::cout << "Sending REJECT for command '" << rejected_command << "' (code " << (int)ccode << ")\n";
    return send_message(sock, "reject", payload.data(), payload.size());
}

// 4. MESSAGE (DIAGNOSTICS)
// Sends a custom message command "message" with diagnostic info
bool send_diagnostic_message(SOCKET sock, const std::string& diagnostic_info) {
    // This assumes the assignment wants a command named "message" containing text.
    // If "message" refers to printing logs locally, this function sends it to peer instead.
    std::vector<uint8_t> payload;

    payload.insert(payload.end(), diagnostic_info.begin(), diagnostic_info.end());

    std::cout << "Sending diagnostic MESSAGE: " << diagnostic_info << "\n";
    return send_message(sock, "message", payload.data(), payload.size());
}

// 5. GETHEADERS MESSAGE
bool send_getheaders(SOCKET sock) {
    std::vector<uint8_t> payload;

    // 1. Version (4 bytes)
    uint8_t tmp4[4];
    write_uint32_le(tmp4, PROTOCOL_VERSION);
    payload.insert(payload.end(), tmp4, tmp4 + 4);

    // 2. Hash count (VarInt) - 1 hash
    write_varint(payload, 1);

    // 3. Block Locator Hashes (32 bytes each)
    // Genesis Block Hash (Mainnet)
    uint8_t genesis_hash[32];
    std::string genesis_hex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    hex_string_to_bytes(genesis_hex, genesis_hash);
    payload.insert(payload.end(), genesis_hash, genesis_hash + 32);

    // 4. Hash Stop (32 bytes of zeros)
    for (int i = 0; i < 32; i++) payload.push_back(0);

    std::cout << "Sending GETHEADERS...\n";
    return send_message(sock, "getheaders", payload.data(), payload.size());
}
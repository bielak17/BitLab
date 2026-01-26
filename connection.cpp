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
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cout << "Socket creation failed: " << WSAGetLastError() << '\n';
        return INVALID_SOCKET;
    }

    struct sockaddr_in peer_addr = {0};
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &peer_addr.sin_addr) != 1) {
        std::cout << "Invalid IP address: " << ip << '\n';
        closesocket(sock);
        return INVALID_SOCKET;
    }

    std::cout << "Connecting to " << ip << ':' << port << " ..." << '\n';
    if (connect(sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) == SOCKET_ERROR) {
        // Quiet fail allows main loop to try next peer cleaner
        // std::cout << "Connect failed: " << WSAGetLastError() << '\n';
        closesocket(sock);
        return INVALID_SOCKET;
    }

    std::cout << "Connected to " << ip << ':' << port << '\n';
    return sock;
}

// Helpers for little-endian encoding
void write_uint32_le(uint8_t* buf, uint32_t val) {
    buf[0] = val & 0xFF; buf[1] = (val >> 8) & 0xFF;
    buf[2] = (val >> 16) & 0xFF; buf[3] = (val >> 24) & 0xFF;
}
void write_uint64_le(uint8_t* buf, uint64_t val) {
    for (int i = 0; i < 8; i++) buf[i] = (val >> (8*i)) & 0xFF;
}

// Compute double SHA256 checksum of payload (first 4 bytes of hash)
void compute_checksum(uint8_t* payload, uint32_t len, uint8_t* checksum_out) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        memset(checksum_out, 0, 4); return;
    }
    
    // First SHA256 hash
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0); memset(checksum_out, 0, 4); return;
    }
    
    if (!CryptHashData(hHash, payload, len, 0)) {
        CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); memset(checksum_out, 0, 4); return;
    }
    
    uint8_t hash1[32]; DWORD hash_len = 32;
    CryptGetHashParam(hHash, HP_HASHVAL, hash1, &hash_len, 0);
    CryptDestroyHash(hHash);
    
    // Second SHA256 hash
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0); memset(checksum_out, 0, 4); return;
    }
    
    CryptHashData(hHash, hash1, 32, 0);
    hash_len = 32;
    uint8_t hash2[32];
    CryptGetHashParam(hHash, HP_HASHVAL, hash2, &hash_len, 0);
    
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
    // 26 bytes: addr_recv
    memset(buf+offset, 0, 26);
    buf[offset+10] = 0xff; buf[offset+11] = 0xff;
    uint8_t ip_bytes[4];
    sscanf(peer_ip.c_str(), "%hhu.%hhu.%hhu.%hhu", &ip_bytes[0], &ip_bytes[1], &ip_bytes[2], &ip_bytes[3]);
    buf[offset+12] = ip_bytes[0]; buf[offset+13] = ip_bytes[1]; buf[offset+14] = ip_bytes[2]; buf[offset+15] = ip_bytes[3];
    buf[offset+16] = (BITCOIN_PORT >> 8) & 0xFF; buf[offset+17] = BITCOIN_PORT & 0xFF;
    offset += 26;
    // 26 bytes: addr_from
    memset(buf+offset, 0, 26);
    buf[offset+10] = 0xff; buf[offset+11] = 0xff;
    buf[offset+12] = 127; buf[offset+13] = 0; buf[offset+14] = 0; buf[offset+15] = 1;
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
std::string recv_with_timeout(SOCKET sock, uint8_t* buffer, int buffer_size, const char* message_name)
{
    // Use internal buffer if none provided, to be safe
    uint8_t temp[4096];
    char* target = buffer ? (char*)buffer : (char*)temp;
    int size = buffer ? buffer_size : 4096;

    int len = recv(sock, target, size, 0);
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
    return std::string(target, len);
}

// --- IMPLEMENTACJE NOWYCH FUNKCJI ---
// (Te funkcje są gotowe do użycia w przyszłości, ale nie są wywoływane domyślnie)

void write_varint(std::vector<uint8_t>& buf, uint64_t val) {
    if (val < 0xfd) {
        buf.push_back((uint8_t)val);
    } else if (val <= 0xffff) {
        buf.push_back(0xfd);
        buf.push_back((uint8_t)(val & 0xFF));
        buf.push_back((uint8_t)((val >> 8) & 0xFF));
    } else if (val <= 0xffffffff) {
        buf.push_back(0xfe);
        for (int i = 0; i < 4; i++) buf.push_back((uint8_t)((val >> (8 * i)) & 0xFF));
    } else {
        buf.push_back(0xff);
        for (int i = 0; i < 8; i++) buf.push_back((uint8_t)((val >> (8 * i)) & 0xFF));
    }
}

void write_varstr(std::vector<uint8_t>& buf, const std::string& s) {
    write_varint(buf, s.size());
    buf.insert(buf.end(), s.begin(), s.end());
}

void hex_string_to_bytes(const std::string& hex, uint8_t* out) {
    for (unsigned int i = 0; i < hex.length() && i < 64; i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        out[31 - (i / 2)] = byte;
    }
}

// 1. PING
bool send_ping(SOCKET sock) {
    uint64_t nonce = ((uint64_t)rand() << 32) | rand();
    uint8_t payload[8];
    write_uint64_le(payload, nonce);
    return send_message(sock, "ping", payload, 8);
}

// 2. ALERT (Simulated)
bool send_alert(SOCKET sock, const std::string& alert_message) {
    std::vector<uint8_t> payload;
    std::vector<uint8_t> content;
    uint8_t tmp4[4], tmp8[8];
    // Dummy construction
    write_uint32_le(tmp4, 1); content.insert(content.end(), tmp4, tmp4+4);
    write_uint64_le(tmp8, (uint64_t)time(nullptr)+7200); content.insert(content.end(), tmp8, tmp8+8);
    write_uint64_le(tmp8, (uint64_t)time(nullptr)+7200); content.insert(content.end(), tmp8, tmp8+8);
    write_uint32_le(tmp4, 1001); content.insert(content.end(), tmp4, tmp4+4);
    write_uint32_le(tmp4, 0); content.insert(content.end(), tmp4, tmp4+4);
    write_varint(content, 0);
    write_uint32_le(tmp4, 0); content.insert(content.end(), tmp4, tmp4+4);
    write_uint32_le(tmp4, PROTOCOL_VERSION); content.insert(content.end(), tmp4, tmp4+4);
    write_varint(content, 0);
    write_uint32_le(tmp4, 1); content.insert(content.end(), tmp4, tmp4+4);
    write_varstr(content, alert_message);
    write_varstr(content, "BitLab");
    write_varstr(content, "");
    write_varstr(payload, std::string(content.begin(), content.end()));
    write_varstr(payload, "");
    return send_message(sock, "alert", payload.data(), payload.size());
}

// 3. REJECT
bool send_reject(SOCKET sock, const std::string& rejected_command, uint8_t ccode, const std::string& reason) {
    std::vector<uint8_t> payload;
    write_varstr(payload, rejected_command);
    payload.push_back(ccode);
    write_varstr(payload, reason);
    return send_message(sock, "reject", payload.data(), payload.size());
}

// 4. MESSAGE
bool send_diagnostic_message(SOCKET sock, const std::string& diagnostic_info) {
    std::vector<uint8_t> payload(diagnostic_info.begin(), diagnostic_info.end());
    return send_message(sock, "message", payload.data(), payload.size());
}

// --- NEW BLOCKS/TX LOGIC ---

void build_inv_payload(std::vector<uint8_t>& payload, InventoryType type, const std::string& hash_hex) {
    write_varint(payload, 1); // Count = 1
    uint8_t tmp4[4];
    write_uint32_le(tmp4, (uint32_t)type);
    payload.insert(payload.end(), tmp4, tmp4 + 4);
    uint8_t hash[32];
    hex_string_to_bytes(hash_hex, hash);
    payload.insert(payload.end(), hash, hash + 32);
}

// 5. GETHEADERS
bool send_getheaders(SOCKET sock, const std::string& start_hash_hex) {
    std::vector<uint8_t> payload;
    uint8_t tmp4[4];
    write_uint32_le(tmp4, PROTOCOL_VERSION);
    payload.insert(payload.end(), tmp4, tmp4 + 4);
    write_varint(payload, 1);
    uint8_t hash[32];
    hex_string_to_bytes(start_hash_hex, hash);
    payload.insert(payload.end(), hash, hash + 32);
    for (int i = 0; i < 32; i++) payload.push_back(0); // Hash stop
    return send_message(sock, "getheaders", payload.data(), payload.size());
}

// 6. GETBLOCKS
bool send_getblocks(SOCKET sock, const std::string& start_hash_hex) {
    std::vector<uint8_t> payload;
    uint8_t tmp4[4];
    write_uint32_le(tmp4, PROTOCOL_VERSION);
    payload.insert(payload.end(), tmp4, tmp4 + 4);
    write_varint(payload, 1);
    uint8_t hash[32];
    hex_string_to_bytes(start_hash_hex, hash);
    payload.insert(payload.end(), hash, hash + 32);
    for (int i = 0; i < 32; i++) payload.push_back(0);
    return send_message(sock, "getblocks", payload.data(), payload.size());
}

// 7. INV
bool send_inv(SOCKET sock, InventoryType type, const std::string& hash_hex) {
    std::vector<uint8_t> payload;
    build_inv_payload(payload, type, hash_hex);
    return send_message(sock, "inv", payload.data(), payload.size());
}

// 8. GETDATA
bool send_getdata(SOCKET sock, InventoryType type, const std::string& hash_hex) {
    std::vector<uint8_t> payload;
    build_inv_payload(payload, type, hash_hex);
    return send_message(sock, "getdata", payload.data(), payload.size());
}

// 9. TX
bool send_tx(SOCKET sock, const std::vector<uint8_t>& raw_tx) {
    std::vector<uint8_t> payload = raw_tx;
    return send_message(sock, "tx", payload.data(), payload.size());
}

// 10. BLOCK
bool send_block(SOCKET sock, const std::vector<uint8_t>& raw_block) {
    std::vector<uint8_t> payload = raw_block;
    return send_message(sock, "block", payload.data(), payload.size());
}

// 11. HEADERS
bool send_headers(SOCKET sock, const std::vector<uint8_t>& raw_headers, uint64_t count) {
    std::vector<uint8_t> payload;
    write_varint(payload, count);
    payload.insert(payload.end(), raw_headers.begin(), raw_headers.end());
    return send_message(sock, "headers", payload.data(), payload.size());
}
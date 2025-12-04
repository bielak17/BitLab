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
        std::cout << "Connect failed: " << WSAGetLastError() << '\n';
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
//to compile (MinGW/g++): g++ connection.cpp main.cpp -o BitLab.exe -lws2_32
//to run: ./BitLab.exe

// own code
#include "connection.h"

// macros
#define DNS_SEED "seed.bitcoin.sipa.be"
#define TIMEOUT_SECONDS 60

int main()
{
    // Initialize Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    auto peers = lookup_dns_seed(DNS_SEED);
    if (peers.empty())
    {
        std::cout << "No peers found." << '\n';
        WSACleanup();
        return 0;
    }

    SOCKET sock = connect_to_peer(peers.back(), BITCOIN_PORT);
    if (sock != INVALID_SOCKET)
    {
        int timeout_ms = TIMEOUT_SECONDS * 1000;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR)
        {
            std::cerr << "setsockopt SO_RCVTIMEO failed: " << WSAGetLastError() << '\n';
            closesocket(sock);
            WSACleanup();
            return 1;
        }
        if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR)
        {
            std::cerr << "setsockopt SO_SNDTIMEO failed: " << WSAGetLastError() << '\n';
            closesocket(sock);
            WSACleanup();
            return 1;
        }
        // build and send version message
        uint8_t payload[100] = {0};
        int payload_len = build_version_payload(payload, peers.back());
        if (!send_message(sock, "version", payload, payload_len))
        {
            std::cout << "Send version failed\n";
            closesocket(sock);
            WSACleanup();
            return 1;
        }
        // wait for version response
        uint8_t buffer[1024];
        if (recv_with_timeout(sock, buffer, sizeof(buffer), "version") == "-1")
        {
            std::cout << "Receive version failed\n";
            closesocket(sock);
            WSACleanup();
            return 1;
        }
        // send verack
        if (!send_message(sock, "verack", nullptr, 0))
        {
            std::cout << "Send verack failed\n";
            closesocket(sock);
            WSACleanup();
            return 1;
        }
        // wait for verack response
        if (recv_with_timeout(sock, buffer, sizeof(buffer), "verack") == "-1")
        {
            std::cout << "Receive verack failed\n";
            closesocket(sock);
            WSACleanup();
            return 1;
        }
        std::cout << "Handshake complete\n";

            // 1. Peer maintenance: PING
        send_ping(sock);

        // Receive PONG? (For testing, we just send, receiving logic handles responses)
        recv_with_timeout(sock, buffer, sizeof(buffer), "wait for pong");

        // 2. Peer maintenance: ALERT
        // Sending a fake network alert
        send_alert(sock, "Warning: This is a BitLab test alert.");

        // 3. Management: REJECT
        // Simulating a rejection of a "tx" message because it was invalid (0x10)
        send_reject(sock, "tx", 0x10, "Transaction invalid format");

        // 4. Management: MESSAGE (Diagnostics)
        // Sending diagnostic info via "message" command
        send_diagnostic_message(sock, "Diagnostics: CPU Load 10%, Mem 20%");

        // 5. Block Inventory: GETHEADERS
        send_getheaders(sock);

        // Wait for HEADERS response
        recv_with_timeout(sock, buffer, sizeof(buffer), "headers");

        // Close connection and cleanup
        closesocket(sock);
        std::cout << "Connection closed\n";
        WSACleanup();
    }
    return 0;
}
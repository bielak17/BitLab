// to compile (MinGW/g++):
// g++ connection.cpp main.cpp -o BitLab.exe -lws2_32 -lcrypt32
// to run:
// ./BitLab.exe

#include "connection.h"
#include <iostream>
#include <vector>
#include <string>

// macros
#define DNS_SEED "seed.bitcoin.sipa.be"
#define TIMEOUT_SECONDS 60

void print_menu()
{
    std::cout << "\n========== BitLab CMD ==========\n";
    std::cout << "1. Send PING\n";
    std::cout << "2. Send GETADDR (discover peers)\n";
    std::cout << "3. Send GETHEADERS\n";
    std::cout << "4. Send ALERT (test)\n";
    std::cout << "5. Send REJECT (tx)\n";
    std::cout << "6. Send DIAGNOSTIC MESSAGE\n";
    std::cout << "7. Wait for incoming message\n";
    std::cout << "8. Send INV (TX)\n";
    std::cout << "9. Send GETDATA (TX)\n";
    std::cout << "10. Send TX (raw test tx)\n";
    std::cout << "11. Send BLOCK (raw test block)\n";
    std::cout << "0. Exit\n";
    std::cout << "================================\n";
    std::cout << "Select option: ";
}

int main()
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    auto peers = lookup_dns_seed(DNS_SEED);
    if (peers.empty())
    {
        std::cout << "No peers found\n";
        WSACleanup();
        return 0;
    }

    SOCKET sock = connect_to_peer(peers.back(), BITCOIN_PORT);
    if (sock == INVALID_SOCKET)
    {
        std::cerr << "Failed to connect to peer\n";
        WSACleanup();
        return 1;
    }

    int timeout_ms = TIMEOUT_SECONDS * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));

    // ===== HANDSHAKE =====
    uint8_t payload[1000] = {0};
    uint8_t buffer[2048];

    int payload_len = build_version_payload(payload, peers.back());
    if (!send_message(sock, "version", payload, payload_len) ||
        recv_with_timeout(sock, buffer, sizeof(buffer), "version") == "-1" ||
        !send_message(sock, "verack", nullptr, 0) ||
        recv_with_timeout(sock, buffer, sizeof(buffer), "verack") == "-1")
    {
        std::cerr << "Handshake failed\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cout << "Handshake complete\n";

    // ===== INTERACTIVE CMD LOOP =====
    bool running = true;
    while (running)
    {
        print_menu();

        int choice;
        std::cin >> choice;

        switch (choice)
        {
            case 1:
                send_ping(sock);
                std::cout << "PING sent\n";
                recv_with_timeout(sock, buffer, sizeof(buffer), "pong");
                break;

            case 2:
            {
                send_getaddr(sock);
                std::string addr_payload = recv_with_timeout(sock, buffer, sizeof(buffer), "addr");
                if (addr_payload != "-1")
                    print_addr_list(addr_payload);
                break;
            }

            case 3:
                send_getheaders(sock);
                recv_with_timeout(sock, buffer, sizeof(buffer), "headers");
                break;

            case 4:
                send_alert(sock, "Warning: BitLab test alert");
                std::cout << "ALERT sent\n";
                break;

            case 5:
                send_reject(sock, "tx", 0x10, "Invalid transaction format");
                std::cout << "REJECT sent\n";
                break;

            case 6:
                send_diagnostic_message(sock, "Diagnostics: CPU 10%, MEM 20%");
                std::cout << "Diagnostic message sent\n";
                break;

            case 7:
                recv_with_timeout(sock, buffer, sizeof(buffer), "any");
                break;

                case 8:
            {
                std::string tx_hash;
                std::cout << "Enter TX hash (hex): ";
                std::cin >> tx_hash;

                send_inv(sock, InventoryType::MSG_TX, tx_hash);
                std::cout << "INV sent\n";
                break;
            }

            case 9:
            {
                std::string tx_hash;
                std::cout << "Enter TX hash (hex): ";
                std::cin >> tx_hash;

                send_getdata(sock, InventoryType::MSG_TX, tx_hash);
                std::cout << "GETDATA sent\n";
                break;
            }

            case 10:
            {
                // Minimal dummy transaction (not valid, but structurally OK)
                std::vector<uint8_t> raw_tx = {
                    0x01, 0x00, 0x00, 0x00, // version
                    0x00,                 // input count
                    0x00,                 // output count
                    0x00, 0x00, 0x00, 0x00 // locktime
                };

                send_tx(sock, raw_tx);
                std::cout << "TX sent\n";
                break;
            }

            case 11:
            {
                // Minimal dummy block payload (header only)
                std::vector<uint8_t> raw_block(80, 0x00);

                send_block(sock, raw_block);
                std::cout << "BLOCK sent\n";
                break;
            }

            case 0:
                running = false;
                break;

            default:
                std::cout << "Unknown option\n";
        }
    }

    closesocket(sock);
    WSACleanup();
    std::cout << "Connection closed\n";

    return 0;
}

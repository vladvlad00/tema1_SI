#include <iostream>
#include <fstream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <cstdlib>
#include <ctime>

#include "common.h"

constexpr int PORT = 8888;
constexpr int MAX_CONNECTIONS = 5;

void generate_key(uint8_t key[16])
{
    for (int i=0;i<16;i++)
        key[i] = rand() % 256;
    printf("Generated key:\n");
    for (int i=0;i<16;i++)
        printf("%02X", key[i]);
    printf("\n");
}

void handle_connection(int sd)
{
    uint8_t k_prim[16];
    uint8_t k[16];
    uint8_t k_enc[16];
    read_key(k_prim);
    generate_key(k);
    AES_KEY ctx;
    AES_set_encrypt_key(k_prim, 128, &ctx);
    AES_encrypt(k, k_enc, &ctx);
    my_write(sd, k_enc, 16);
    close(sd);
}

int main()
{
    srand(time(0));
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (!sock)
    {
        perror("Socket failed");
        exit(1);
    }
    int opt = true;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof(opt)) < 0)
    {
        perror("Setsockopt failed");
        exit(1);
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(sock, (sockaddr*)&address, sizeof(address)) < 0)
    {
        perror("Bind failed");
        exit(1);
    }
    std::cout << "Listening on port " << PORT << '\n';
    if (listen(sock, MAX_CONNECTIONS) < 0)
    {
        perror("Listen failed");
        exit(1);
    }
    std::cout << "Waiting for connections\n";
    int addrlen = sizeof(address);
    while (true)
    {
        int sd = accept(sock, (sockaddr*)&address, (socklen_t*)&addrlen);
        if (sd < 0)
        {
            perror("Accept failed");
            exit(1);
        }
        std::cout << "New connection from " << inet_ntoa(address.sin_addr) << ':' << ntohs(address.sin_port) << '\n';

        handle_connection(sd);
    }
    return 0;
}

#include <iostream>
#include <fstream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <cstdlib>
#include <ctime>
#include <cstring>

#include "common.h"

constexpr int PORT = 8889;
constexpr int MAX_CONNECTIONS = 5;

void get_key(uint8_t k[16], uint8_t k_enc[16])
{
    uint8_t k_prim[16];
    read_key(k_prim);
    AES_KEY ctx;
    AES_set_decrypt_key(k_prim, 128, &ctx);
    AES_decrypt(k_enc, k, &ctx);
    printf("Got key:\n");
    for (int i=0; i<16; i++)
        printf("%02X", k[i]);
    printf("\n");
}

void get_output_ecb(int sd, uint8_t k[16])
{
    uint8_t file_data[16];
    uint8_t file_data_enc[16];
    std::ofstream file("output", std::ios::binary);
    AES_KEY ctx;
    AES_set_decrypt_key(k, 128, &ctx);
    bool first = true;
    while (true)
    {
        int to_read;
        my_read(sd, &to_read, sizeof(to_read));
        if (to_read != 16)
        {
            file.write((char*)file_data, 16-to_read);
            break;
        }
        else if (!first)
            file.write((char*)file_data, 16);
        my_read(sd, file_data_enc, 16);
        AES_decrypt(file_data_enc, file_data, &ctx);
        first = false;
    }
}

void get_output_cfb(int sd, uint8_t k[16])
{
    uint8_t iv[16];
    read_iv(iv);
    uint8_t file_data_enc[16];
    uint8_t file_data[16];
    std::ofstream file("output", std::ios::binary);
    AES_KEY ctx;
    AES_set_encrypt_key(k, 128, &ctx);
    bool first = true;
    while (true)
    {
        int to_read;
        my_read(sd, &to_read, sizeof(to_read));
        if (to_read != 16)
        {
            file.write((char*)file_data, 16-to_read);
            break;
        }
        else if (!first)
            file.write((char*)file_data, 16);
        my_read(sd, file_data_enc, 16);
        AES_encrypt(iv, iv, &ctx);
        for (int i=0;i<16;i++)
            file_data[i] = iv[i] ^ file_data_enc[i];
        memcpy(iv, file_data_enc, 16);
        first = false;
    }
}

void handle_connection(int sd)
{
    EncryptionMode mode;
    my_read(sd, &mode, sizeof(mode));

    uint8_t k_enc[16];
    my_read(sd, k_enc, 16);

    uint8_t k[16];
    get_key(k, k_enc);

    int ok = 1;
    my_write(sd, &ok, sizeof(ok));

    if (mode == EncryptionMode::ECB)
        get_output_ecb(sd, k);
    else
        get_output_cfb(sd, k);

    close(sd);
}

int main()
{
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

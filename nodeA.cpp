#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <filesystem>
#include "common.h"

const char* km_ip = "127.0.0.1";
const int km_port = 8888;
const char* b_ip = "127.0.0.1";
const int b_port = 8889;

int connect_to_server(const char* ip, int port)
{
    int sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd == 0)
    {
        perror("Socket failed");
        exit(1);
    }
    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_port = htons(port);

    if (connect(sd, (sockaddr *) &server, sizeof(sockaddr)) < 0)
    {
        perror("Connect failed");
        exit(1);
    }
    return sd;
}

void get_key(uint8_t k[16], uint8_t k_enc[16])
{
    int sd = connect_to_server(km_ip, km_port);
    my_read(sd, k_enc, 16);
    close(sd);
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

void transfer_file_ecb(int sd, const char* path, uint8_t key[16])
{
    int file_size = (int)std::filesystem::file_size(path);
    std::ifstream file(path, std::ios::binary);
    uint8_t file_data[16];
    uint8_t encrypted_file_data[16];
    int padding = 0;
    AES_KEY ctx;
    AES_set_encrypt_key(key, 128, &ctx);
    for (int i=0;i<file_size; i+=16)
    {
        int to_read = std::min(16, file_size - i);
        file.read((char*)file_data, to_read);
        if (to_read < 16)
        {
            for (int j = to_read; j < 16; j++)
                file_data[j] = 0;
            padding = 16 - to_read;
            to_read = 16;
        }
        AES_encrypt(file_data, encrypted_file_data, &ctx);
        my_write(sd, &to_read, sizeof(to_read));
        my_write(sd, encrypted_file_data, 16);
    }
    my_write(sd, &padding, sizeof(padding));
}

void transfer_file_cfb(int sd, const char* path, uint8_t key[16])
{
    uint8_t iv[16];
    read_iv(iv);
    int file_size = (int)std::filesystem::file_size(path);
    std::ifstream file(path, std::ios::binary);
    uint8_t file_data[16];
    int padding = 0;
    AES_KEY ctx;
    AES_set_encrypt_key(key, 128, &ctx);
    for (int i=0;i<file_size; i+=16)
    {
        int to_read = std::min(16, file_size - i);
        file.read((char*)file_data, to_read);
        if (to_read < 16)
        {
            for (int j = to_read; j < 16; j++)
                file_data[j] = 0;
            padding = 16 - to_read;
            to_read = 16;
        }
        AES_encrypt(iv, iv, &ctx);
        for (int j=0;j<16;j++)
            iv[j] ^= file_data[j];
        my_write(sd, &to_read, sizeof(to_read));
        my_write(sd, iv, 16);
    }
    my_write(sd, &padding, sizeof(padding));
}

void transfer_file(const char* path, EncryptionMode mode, uint8_t key[16], uint8_t key_enc[16])
{
    int sd = connect_to_server(b_ip, b_port);
    my_write(sd, &mode, sizeof(mode));
    my_write(sd, key_enc, 16);
    int ok = 0;
    my_read(sd, &ok, sizeof(ok));
    if (ok != 1)
        exit(1);
    if (mode == EncryptionMode::ECB)
        transfer_file_ecb(sd, path, key);
    else if (mode == EncryptionMode::CFB)
        transfer_file_cfb(sd, path, key);
}

int main()
{
    uint8_t key[16];
    uint8_t key_enc[16];
    get_key(key, key_enc);
    transfer_file("common.h", EncryptionMode::ECB, key, key_enc);
    return 0;
}

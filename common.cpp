//
// Created by vlad on 17.10.2021.
//

#include "common.h"

void socket_read(int sd, void* buffer, int length, const char* buffer_name)
{
    auto bytes_read = read(sd, buffer, length);
    printf("Read %ld out of %d bytes into %s:\n", bytes_read, length, buffer_name);
    for (int i=0;i<length;i++)
    {
        printf("%02X", ((uint8_t*)buffer)[i]);
    }
    printf("\n");
}

void socket_write(int sd, void* buffer, int length, const char* buffer_name)
{
    auto bytes_written = write(sd, buffer, length);
    printf("Wrote %ld out of %d bytes from %s:\n", bytes_written, length, buffer_name);
    for (int i=0;i<length;i++)
        printf("%02X", ((uint8_t*)buffer)[i]);
    printf("\n");
}

void read_key(uint8_t key[16])
{
    std::ifstream f("key", std::ios::binary);
    f.read((char*)key, 16);
}

void read_iv(uint8_t iv[16])
{
    std::ifstream f("iv", std::ios::binary);
    f.read((char*)iv, 16);
}
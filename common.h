//
// Created by vlad on 17.10.2021.
//

#ifndef TEMA1_COMMON_H
#define TEMA1_COMMON_H

#include <unistd.h>
#include <iostream>
#include <fstream>

enum class EncryptionMode
{
    ECB,
    CFB
};

void socket_read(int sd, void* buffer, int length, const char* buffer_name);
void socket_write(int sd, void* buffer, int length, const char* buffer_name);
void read_key(uint8_t key[16]);
void read_iv(uint8_t iv[16]);

#define my_read(sd, buffer, length) \
{ \
    socket_read(sd, buffer, length, #buffer); \
}

#define my_write(sd, buffer, length) \
{ \
    socket_write(sd, buffer, length, #buffer); \
}

#endif //TEMA1_COMMON_H

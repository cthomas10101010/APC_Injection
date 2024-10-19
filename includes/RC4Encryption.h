#ifndef RC4ENCRYPTION_H
#define RC4ENCRYPTION_H

#include <cstddef>  // Include for size_t

void RC4Encrypt(unsigned char* data, size_t dataLen, unsigned char* key, size_t keyLen);

#endif

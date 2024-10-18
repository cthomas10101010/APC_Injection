#include "RC4Encryption.h"

void RC4Encrypt(unsigned char* data, size_t dataLen, unsigned char* key, size_t keyLen) {
    unsigned char S[256];
    unsigned char j = 0;
    int i = 0;

    for (i = 0; i < 256; i++) {
        S[i] = i;
    }

    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLen]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }

    i = 0;
    j = 0;

    for (size_t n = 0; n < dataLen; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;

        data[n] ^= S[(S[i] + S[j]) % 256];
    }
}

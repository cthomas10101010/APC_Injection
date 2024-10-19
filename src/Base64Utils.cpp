#include "Base64Utils.h"
#include <string>
#include <vector>

// Function to encode payload to base64 for further obfuscation
std::string Base64Encode(const unsigned char* buffer, size_t length) {
    static const char* base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    std::string encoded_data;
    int val = 0, valb = -6;
    for (size_t i = 0; i < length; i++) {
        val = (val << 8) + buffer[i];
        valb += 8;
        while (valb >= 0) {
            encoded_data.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) encoded_data.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (encoded_data.size() % 4) encoded_data.push_back('=');
    return encoded_data;
}

// Function to decode the base64 payload
std::vector<unsigned char> Base64Decode(const std::string& input) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    std::vector<unsigned char> decoded_data;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : input) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            decoded_data.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return decoded_data;
}

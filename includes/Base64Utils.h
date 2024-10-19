#ifndef BASE64UTILS_H
#define BASE64UTILS_H

#include <string>
#include <vector>

// Function to encode data in base64
std::string Base64Encode(const unsigned char* data, unsigned long long length);

// Function to decode base64 string
std::vector<unsigned char> Base64Decode(const std::string& encoded);

#endif // BASE64UTILS_H

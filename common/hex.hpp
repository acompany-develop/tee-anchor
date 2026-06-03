#pragma once
//
// バイト列の lowercase hex 文字列化。Chip ID やフィンガープリント表示用。
//
#include <cstdint>
#include <string>
#include <vector>

namespace tee_anchor {

inline std::string to_hex_lower(const uint8_t* data, size_t len) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        s.push_back(d[data[i] >> 4]);
        s.push_back(d[data[i] & 0x0f]);
    }
    return s;
}

inline std::string to_hex_lower(const std::vector<uint8_t>& v) {
    return to_hex_lower(v.data(), v.size());
}

}  // namespace tee_anchor

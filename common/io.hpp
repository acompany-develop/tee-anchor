#pragma once
//
// 小さなファイル I/O ヘルパ。複数サブコマンドで共有する。
//
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <vector>

#include "error.hpp"

namespace tee_anchor {

inline std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) throw TeeAnchorError("cannot open for reading: " + path);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(ifs)),
                                std::istreambuf_iterator<char>());
}

// ファイルを書き出した後 chmod でモードを設定する。
// 厳密には create と chmod の間に短い race があるが、PoC ではこれで十分。
inline void write_file(const std::string& path,
                       const void* data, size_t len,
                       mode_t mode) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) throw TeeAnchorError("cannot open for writing: " + path);
    ofs.write(static_cast<const char*>(data), static_cast<std::streamsize>(len));
    if (!ofs) throw TeeAnchorError("write failed: " + path);
    ofs.close();
    if (chmod(path.c_str(), mode) != 0) {
        throw TeeAnchorError("chmod failed: " + path);
    }
}

inline void write_file(const std::string& path,
                       const std::string& content,
                       mode_t mode) {
    write_file(path, content.data(), content.size(), mode);
}

inline bool path_exists(const std::string& path) {
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
}

}  // namespace tee_anchor

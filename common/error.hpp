#pragma once
//
// TEE Anchor 共通の例外型と OpenSSL エラー送出ヘルパ。
// OpenSSL 関数が失敗したら throw_openssl_error() でメッセージを整形して投げる。
//
#include <stdexcept>
#include <string>

#include <openssl/err.h>

namespace tee_anchor {

class TeeAnchorError : public std::runtime_error {
public:
    explicit TeeAnchorError(const std::string& msg) : std::runtime_error(msg) {}
};

// 直近の OpenSSL エラーを context 付きで TeeAnchorError として投げる。
[[noreturn]] inline void throw_openssl_error(const std::string& context) {
    const unsigned long code = ERR_get_error();
    std::string msg = context;
    if (code != 0) {
        char buf[256] = {0};
        ERR_error_string_n(code, buf, sizeof(buf));
        msg += ": ";
        msg += buf;
    } else {
        msg += ": (no OpenSSL error on stack)";
    }
    throw TeeAnchorError(msg);
}

[[noreturn]] inline void throw_openssl_error(const char* context) {
    throw_openssl_error(std::string(context));
}

}  // namespace tee_anchor

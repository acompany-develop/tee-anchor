#pragma once
//
// 組織 CA / endorsement cert 発行で共有する PKI ヘルパ。
// 小さな関数群なので header-only (inline) で提供する。
//
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "error.hpp"
#include "io.hpp"
#include "openssl_raii.hpp"

namespace tee_anchor::pki {

// -- 文字列 -----------------------------------------------------------------
inline std::string trim(const std::string& s) {
    auto b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return "";
    auto e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

// "CN=Foo,O=Bar,..." を X509_NAME にパース。
// PoC 用の単純実装 (カンマ分割のみ。引用/エスケープ未対応)。
inline X509NamePtr parse_dn(const std::string& dn) {
    X509NamePtr name(X509_NAME_new());
    if (!name) throw_openssl_error("X509_NAME_new");

    size_t pos = 0;
    while (pos < dn.size()) {
        size_t comma = dn.find(',', pos);
        std::string rdn = (comma == std::string::npos)
            ? dn.substr(pos) : dn.substr(pos, comma - pos);

        size_t eq = rdn.find('=');
        if (eq == std::string::npos) {
            throw TeeAnchorError("invalid DN segment (no '='): " + rdn);
        }
        std::string key = trim(rdn.substr(0, eq));
        std::string val = trim(rdn.substr(eq + 1));
        if (key.empty() || val.empty()) {
            throw TeeAnchorError("invalid DN segment: " + rdn);
        }
        if (X509_NAME_add_entry_by_txt(
                name.get(), key.c_str(), MBSTRING_UTF8,
                reinterpret_cast<const unsigned char*>(val.c_str()),
                -1, -1, 0) != 1) {
            throw_openssl_error("X509_NAME_add_entry_by_txt (" + key + ")");
        }
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
    return name;
}

// -- 鍵 ---------------------------------------------------------------------

// 曲線名から ECDSA-with-SHA-x のダイジェストを返す。
inline const EVP_MD* sig_md_for_curve(const std::string& curve) {
    if (curve == "P-256" || curve == "secp256r1" || curve == "prime256v1") return EVP_sha256();
    if (curve == "P-384" || curve == "secp384r1")                          return EVP_sha384();
    if (curve == "P-521" || curve == "secp521r1")                          return EVP_sha512();
    throw TeeAnchorError("unsupported curve: " + curve +
                         " (supported: P-256, P-384, P-521)");
}

// 既存鍵から適切な署名 MD を選ぶ。EC の場合は曲線名から自動判定する。
inline const EVP_MD* digest_for_signing_key(EVP_PKEY* pkey) {
    const int id = EVP_PKEY_base_id(pkey);
    if (id == EVP_PKEY_EC) {
        char buf[80] = {0};
        size_t out_len = 0;
        if (EVP_PKEY_get_utf8_string_param(
                pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                buf, sizeof(buf) - 1, &out_len) != 1) {
            throw_openssl_error("EVP_PKEY_get_utf8_string_param (group name)");
        }
        return sig_md_for_curve(std::string(buf, out_len));
    }
    if (id == EVP_PKEY_RSA) return EVP_sha256();
    if (id == EVP_PKEY_ED25519 || id == EVP_PKEY_ED448) return nullptr;
    return EVP_sha256();
}

inline EvpPkeyPtr gen_ec_key(const std::string& curve) {
    EVP_PKEY* raw = EVP_EC_gen(curve.c_str());
    if (!raw) throw_openssl_error("EVP_EC_gen (" + curve + ")");
    return EvpPkeyPtr(raw);
}

// -- I/O --------------------------------------------------------------------

inline EvpPkeyPtr load_pem_private_key(const std::string& path) {
    auto bytes = read_file(path);
    BioPtr bio(BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size())));
    if (!bio) throw_openssl_error("BIO_new_mem_buf");
    EVP_PKEY* raw = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (!raw) throw_openssl_error("PEM_read_bio_PrivateKey (" + path + ")");
    return EvpPkeyPtr(raw);
}

inline X509Ptr load_pem_cert(const std::string& path) {
    auto bytes = read_file(path);
    BioPtr bio(BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size())));
    if (!bio) throw_openssl_error("BIO_new_mem_buf");
    X509* raw = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (!raw) throw_openssl_error("PEM_read_bio_X509 (" + path + ")");
    return X509Ptr(raw);
}

inline X509CrlPtr load_pem_crl(const std::string& path) {
    auto bytes = read_file(path);
    BioPtr bio(BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size())));
    if (!bio) throw_openssl_error("BIO_new_mem_buf");
    X509_CRL* raw = PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr);
    if (!raw) throw_openssl_error("PEM_read_bio_X509_CRL (" + path + ")");
    return X509CrlPtr(raw);
}

inline std::vector<uint8_t> pem_private_key(EVP_PKEY* pkey) {
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio) throw_openssl_error("BIO_new (mem)");
    if (PEM_write_bio_PrivateKey(bio.get(), pkey, nullptr, nullptr, 0,
                                 nullptr, nullptr) != 1) {
        throw_openssl_error("PEM_write_bio_PrivateKey");
    }
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem);
    return std::vector<uint8_t>(mem->data, mem->data + mem->length);
}

inline std::vector<uint8_t> pem_cert(X509* cert) {
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio) throw_openssl_error("BIO_new (mem)");
    if (PEM_write_bio_X509(bio.get(), cert) != 1) {
        throw_openssl_error("PEM_write_bio_X509");
    }
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem);
    return std::vector<uint8_t>(mem->data, mem->data + mem->length);
}

// -- 拡張 -------------------------------------------------------------------

// 159-bit のランダムな正の整数を ASN1_INTEGER として返す (RFC 5280 推奨範囲)。
inline Asn1IntPtr random_serial() {
    BnPtr bn(BN_new());
    if (!bn) throw_openssl_error("BN_new");
    if (BN_rand(bn.get(), 159, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1) {
        throw_openssl_error("BN_rand");
    }
    Asn1IntPtr ai(ASN1_INTEGER_new());
    if (!ai) throw_openssl_error("ASN1_INTEGER_new");
    if (!BN_to_ASN1_INTEGER(bn.get(), ai.get())) {
        throw_openssl_error("BN_to_ASN1_INTEGER");
    }
    return ai;
}

inline void add_v3_ext(X509* cert, X509V3_CTX* ctx, int nid, const char* value) {
    X509ExtPtr ext(X509V3_EXT_conf_nid(nullptr, ctx, nid, value));
    if (!ext) {
        throw_openssl_error(std::string("X509V3_EXT_conf_nid (nid=") +
                            std::to_string(nid) + ")");
    }
    if (X509_add_ext(cert, ext.get(), -1) != 1) {
        throw_openssl_error("X509_add_ext");
    }
}

inline Asn1ObjectPtr make_oid(const char* oid_str) {
    Asn1ObjectPtr obj(OBJ_txt2obj(oid_str, /*no_name=*/1));
    if (!obj) throw_openssl_error("OBJ_txt2obj");
    return obj;
}

}  // namespace tee_anchor::pki

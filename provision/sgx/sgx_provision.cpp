//
// sgx_provision.cpp
//
// Phase 1 / SGX:
//   Quote から PCK 証明書チェーンを抽出 → Intel SGX Root CA(公開鍵ハードコード)
//   でチェーン検証 → 検証通過後に PPID を抽出する。
//
// CRL チェックは Phase 1 ではスコープ外。
//
#include "sgx_provision.hpp"

#include <algorithm>
#include <cstdint>
#include <string>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>

#include "error.hpp"
#include "intel_sgx_root_pubkey.hpp"

namespace tee_anchor::sgx {

namespace {

// ---- Quote バイナリのレイアウト（SGX ECDSA Quote v3）------------------------
//  Header(48) | ReportBody(384) | sig_len(4) | signature_data...
//  signature_data = sgx_ql_ecdsa_sig_data_t:
//    sig[64] | attest_pub_key[64] | qe_report(384) | qe_report_sig[64]
//    | auth_data( u16 size + size bytes )
//    | certification_data( u16 cert_key_type + u32 size + size bytes )
constexpr size_t kQuoteHeaderSize = 48;
constexpr size_t kReportBodySize  = 384;
constexpr size_t kSigLenFieldSize = 4;
// sig + attest_pub_key + qe_report + qe_report_sig
constexpr size_t kEcdsaFixedSize  = 64 + 64 + kReportBodySize + 64;  // 576
constexpr uint16_t kCertTypePckCertChain = 5;

// quote[off] から n バイト読めることを保証（足りなければ例外）。
void need(const std::vector<uint8_t>& q, size_t off, size_t n, const char* what) {
    if (off > q.size() || n > q.size() - off) {
        throw TeeAnchorError(std::string("quote too short while reading ") + what);
    }
}

uint16_t rd_u16le(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

uint32_t rd_u32le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

Asn1ObjectPtr make_oid(const char* oid) {
    Asn1ObjectPtr obj(OBJ_txt2obj(oid, /*no_name=*/1));
    if (!obj) throw_openssl_error("OBJ_txt2obj");
    return obj;
}

// SGX Extension(SEQUENCE OF SEQUENCE{OID, value}) の DER を走査し、
// target OID に一致する要素の value(TLV)の「内容バイト列」を返す。
std::optional<std::vector<uint8_t>>
walk_extension(const uint8_t* der, long der_len, const ASN1_OBJECT* target) {
    const unsigned char* p = der;
    long len = 0;
    int tag = 0, xclass = 0;

    int ret = ASN1_get_object(&p, &len, &tag, &xclass, der_len);
    if ((ret & 0x80) || tag != V_ASN1_SEQUENCE) return std::nullopt;
    const unsigned char* end = p + len;

    while (p < end) {
        long elem_len = 0;
        ret = ASN1_get_object(&p, &elem_len, &tag, &xclass, end - p);
        if ((ret & 0x80) || tag != V_ASN1_SEQUENCE) return std::nullopt;
        const unsigned char* elem_content = p;
        const unsigned char* elem_end = p + elem_len;

        const unsigned char* op = elem_content;
        ASN1_OBJECT* raw_obj = d2i_ASN1_OBJECT(nullptr, &op, elem_end - elem_content);
        if (!raw_obj) return std::nullopt;
        Asn1ObjectPtr obj(raw_obj);

        if (OBJ_cmp(obj.get(), target) == 0) {
            const unsigned char* vp = op;
            long vlen = 0;
            int vtag = 0, vclass = 0;
            int r2 = ASN1_get_object(&vp, &vlen, &vtag, &vclass, elem_end - op);
            if (r2 & 0x80) return std::nullopt;
            return std::vector<uint8_t>(vp, vp + vlen);
        }
        p = elem_end;
    }
    return std::nullopt;
}

// EC 公開鍵を SEC1 uncompressed point 形式(0x04 || X || Y)で取り出す。
std::vector<uint8_t> get_ec_pubkey_uncompressed(X509* cert) {
    EVP_PKEY* pkey = X509_get0_pubkey(cert);  // borrowed
    if (!pkey) throw_openssl_error("X509_get0_pubkey");

    size_t len = 0;
    if (EVP_PKEY_get_octet_string_param(
            pkey, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &len) != 1) {
        throw_openssl_error("EVP_PKEY_get_octet_string_param (size)");
    }
    std::vector<uint8_t> pub(len);
    if (EVP_PKEY_get_octet_string_param(
            pkey, OSSL_PKEY_PARAM_PUB_KEY, pub.data(), len, &len) != 1) {
        throw_openssl_error("EVP_PKEY_get_octet_string_param");
    }
    pub.resize(len);
    return pub;
}

bool is_self_signed(X509* c) {
    return X509_NAME_cmp(X509_get_subject_name(c),
                        X509_get_issuer_name(c)) == 0;
}

// チェーン内で「他のどの証明書からも issuer として参照されていない」証明書を leaf として返す。
// DCAP 既定は chain[0] が leaf だが、順序非依存にしておく。
X509* find_leaf(const std::vector<X509Ptr>& chain) {
    for (const auto& c : chain) {
        if (is_self_signed(c.get())) continue;  // root は除外
        bool issuer_of_some = false;
        for (const auto& other : chain) {
            if (other.get() == c.get()) continue;
            if (X509_NAME_cmp(X509_get_subject_name(c.get()),
                              X509_get_issuer_name(other.get())) == 0) {
                issuer_of_some = true;
                break;
            }
        }
        if (!issuer_of_some) return c.get();
    }
    return nullptr;
}

}  // namespace

std::vector<X509Ptr>
extract_pck_chain_from_quote(const std::vector<uint8_t>& quote) {
    size_t off = kQuoteHeaderSize + kReportBodySize + kSigLenFieldSize;
    need(quote, off, kEcdsaFixedSize, "ecdsa signature fixed part");
    off += kEcdsaFixedSize;

    need(quote, off, 2, "auth_data size");
    const uint16_t auth_size = rd_u16le(&quote[off]);
    off += 2;
    need(quote, off, auth_size, "auth_data body");
    off += auth_size;

    need(quote, off, 6, "certification_data header");
    const uint16_t cert_key_type = rd_u16le(&quote[off]);
    const uint32_t cert_size = rd_u32le(&quote[off + 2]);
    off += 6;
    need(quote, off, cert_size, "certification_data body");

    if (cert_key_type != kCertTypePckCertChain) {
        throw TeeAnchorError(
            "unsupported cert_key_type=" + std::to_string(cert_key_type) +
            " (expected 5 = PCK_CERT_CHAIN); quote lacks an embedded PCK cert chain");
    }

    BioPtr bio(BIO_new_mem_buf(quote.data() + off, static_cast<int>(cert_size)));
    if (!bio) throw_openssl_error("BIO_new_mem_buf");

    std::vector<X509Ptr> chain;
    while (true) {
        X509* raw = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
        if (!raw) break;
        chain.emplace_back(raw);
    }
    // 最後の PEM_read_bio_X509 は EOF で失敗するため、エラースタックをクリア。
    ERR_clear_error();

    if (chain.empty()) {
        throw TeeAnchorError("no PCK certificates found in quote certification_data");
    }
    return chain;
}

X509* verify_pck_chain(const std::vector<X509Ptr>& chain) {
    if (chain.empty()) throw TeeAnchorError("empty PCK chain");

    // 1. 自己署名 root を見つける
    X509* root = nullptr;
    for (const auto& c : chain) {
        if (is_self_signed(c.get())) { root = c.get(); break; }
    }
    if (!root) {
        throw TeeAnchorError("no self-signed root certificate in PCK chain");
    }

    // 2. root 公開鍵をハードコード値と bit-for-bit 比較
    const std::vector<uint8_t> root_pub = get_ec_pubkey_uncompressed(root);
    if (root_pub.size() != kIntelSgxRootPubkey.size() ||
        !std::equal(root_pub.begin(), root_pub.end(),
                    kIntelSgxRootPubkey.begin())) {
        throw TeeAnchorError(
            "PCK chain root public key does not match the hardcoded "
            "Intel SGX Root CA public key");
    }

    // 3. leaf を特定
    X509* leaf = find_leaf(chain);
    if (!leaf) {
        throw TeeAnchorError("could not identify leaf certificate in PCK chain");
    }

    // 4. X509_STORE に root を信頼アンカーとして登録し、leaf を検証
    X509StorePtr store(X509_STORE_new());
    if (!store) throw_openssl_error("X509_STORE_new");
    if (X509_STORE_add_cert(store.get(), root) != 1) {
        throw_openssl_error("X509_STORE_add_cert (root)");
    }

    // intermediates(= root でも leaf でもない全要素)を untrusted スタックに積む
    SkX509Ptr untrusted(sk_X509_new_null());
    if (!untrusted) throw_openssl_error("sk_X509_new_null");
    for (const auto& c : chain) {
        if (c.get() == root || c.get() == leaf) continue;
        if (sk_X509_push(untrusted.get(), c.get()) == 0) {
            throw_openssl_error("sk_X509_push");
        }
    }

    X509StoreCtxPtr ctx(X509_STORE_CTX_new());
    if (!ctx) throw_openssl_error("X509_STORE_CTX_new");
    if (X509_STORE_CTX_init(ctx.get(), store.get(), leaf, untrusted.get()) != 1) {
        throw_openssl_error("X509_STORE_CTX_init");
    }
    // CRL チェックは Phase 1 では行わない（デフォルトで OFF）。

    if (X509_verify_cert(ctx.get()) != 1) {
        const int err = X509_STORE_CTX_get_error(ctx.get());
        throw TeeAnchorError(
            std::string("PCK chain verification failed: ") +
            X509_verify_cert_error_string(err));
    }
    return leaf;
}

std::optional<std::vector<uint8_t>>
find_sgx_extension_octet(X509* pck_leaf, const char* oid) {
    Asn1ObjectPtr ext_oid = make_oid(OID_SGX_EXTENSION);
    const int idx = X509_get_ext_by_OBJ(pck_leaf, ext_oid.get(), -1);
    if (idx < 0) return std::nullopt;

    X509_EXTENSION* ext = X509_get_ext(pck_leaf, idx);
    if (!ext) return std::nullopt;
    const ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
    if (!data) return std::nullopt;

    Asn1ObjectPtr target = make_oid(oid);
    return walk_extension(ASN1_STRING_get0_data(data), ASN1_STRING_length(data),
                          target.get());
}

std::vector<uint8_t> extract_ppid_from_quote(const std::vector<uint8_t>& quote) {
    auto chain = extract_pck_chain_from_quote(quote);
    X509* leaf = verify_pck_chain(chain);
    auto ppid = find_sgx_extension_octet(leaf, OID_SGX_PPID);
    if (!ppid) {
        throw TeeAnchorError("PPID (OID 1.2.840.113741.1.13.1.1) not found in PCK cert");
    }
    return *ppid;
}

}  // namespace tee_anchor::sgx

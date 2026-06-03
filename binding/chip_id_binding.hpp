#pragma once
//
// ChipIdBinding 拡張の DER エンコード / デコード。
//
// design.md より:
//   ChipIdBinding ::= SEQUENCE {
//       teeType    ENUMERATED { sgx(0), tdx(1), sevSnp(2), armCca(3) },
//       chipId     OCTET STRING,
//       issuedAt   GeneralizedTime
//   }
//
// 組織エンドースメント証明書には OID 1.3.6.1.4.1.99999.1.1 の Critical 拡張として
// このバイト列が格納される。provision は encode、verify は decode を使う。
//
#include <cstdint>
#include <string>
#include <vector>

#include <openssl/x509.h>

#include "openssl_raii.hpp"

namespace tee_anchor::binding {

constexpr uint8_t kTeeTypeSgx    = 0;
constexpr uint8_t kTeeTypeTdx    = 1;
constexpr uint8_t kTeeTypeSevSnp = 2;
constexpr uint8_t kTeeTypeArmCca = 3;

// 開発中の暫定 OID (組織 PEN を取得するまでのプレースホルダ)
constexpr const char* kOidChipIdBinding = "1.3.6.1.4.1.99999.1.1";

struct ChipIdBinding {
    uint8_t              tee_type;
    std::vector<uint8_t> chip_id;
    std::string          issued_at;  // GeneralizedTime 文字列 "YYYYMMDDHHMMSSZ"
};

// ChipIdBinding を DER エンコード。issuedAt は現在時刻(UTC)を埋める。
std::vector<uint8_t>
encode_chip_id_binding(uint8_t tee_type,
                       const std::vector<uint8_t>& chip_id);

// 上の encode 結果を X.509 拡張 (Critical, OID kOidChipIdBinding) として包装する。
X509ExtPtr make_chip_id_binding_extension(const std::vector<uint8_t>& binding_der);

// DER バイト列 (SEQUENCE 全体) から ChipIdBinding をデコード。
ChipIdBinding decode_chip_id_binding(const uint8_t* der, size_t der_len);

// 証明書から ChipIdBinding 拡張を取り出してデコード。
// 拡張が無いか壊れている場合は TeeAnchorError。
ChipIdBinding extract_chip_id_binding(X509* cert);

inline const char* tee_type_name(uint8_t t) {
    switch (t) {
        case kTeeTypeSgx:    return "sgx";
        case kTeeTypeTdx:    return "tdx";
        case kTeeTypeSevSnp: return "sev-snp";
        case kTeeTypeArmCca: return "arm-cca";
        default:             return "unknown";
    }
}

}  // namespace tee_anchor::binding

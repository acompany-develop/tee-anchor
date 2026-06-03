#pragma once
//
// SGX provision: Quote から PCK 証明書チェーンを取り出し、
// Intel SGX Root CA(ハードコード公開鍵)で検証した上で Chip ID(PPID) を抽出する処理。
//
// 方針: TEE Anchor 本体はベンダー中立のため SGX SDK には依存しない。
// Quote(quote.dat) のバイナリ構造は自前で読み、PCK 証明書は OpenSSL で扱う。
//
#include <cstdint>
#include <optional>
#include <vector>

#include "openssl_raii.hpp"

namespace tee_anchor::sgx {

// SGX Extension の OID（Intel PCK Certificate Specification）
inline constexpr const char* OID_SGX_EXTENSION = "1.2.840.113741.1.13.1";
inline constexpr const char* OID_SGX_PPID       = "1.2.840.113741.1.13.1.1";
inline constexpr const char* OID_SGX_PCEID      = "1.2.840.113741.1.13.1.3";
inline constexpr const char* OID_SGX_FMSPC      = "1.2.840.113741.1.13.1.4";

// ECDSA Quote(v3) の Certification Data に格納された PCK 証明書チェーン全体を
// 取り出す。cert_key_type が 5(PCK_CERT_CHAIN) でない場合は TeeAnchorError。
// 順序は通常 [leaf, intermediate, root]（DCAP 既定）だが、本関数は順序を保証しない。
// 検証は行わない。verify_pck_chain() を別途呼ぶこと。
std::vector<X509Ptr>
extract_pck_chain_from_quote(const std::vector<uint8_t>& quote);

// PCK 証明書チェーンを検証する：
//   1. チェーン内の自己署名証明書(root)を見つける
//   2. その公開鍵がハードコードした Intel SGX Root CA 公開鍵と
//      bit-for-bit 一致するか確認
//   3. 一致した root を信頼アンカーとして OpenSSL X509_STORE に投入し、
//      leaf を intermediate 経由で検証
// CRL チェックは行わない（Phase 1 ではスコープ外）。
// 検証に成功すると leaf 証明書(借用ポインタ; chain の寿命に従う)を返す。
// 失敗時は TeeAnchorError。
X509* verify_pck_chain(const std::vector<X509Ptr>& chain);

// PCK 証明書の SGX Extension から、指定 OID の OCTET STRING 値を取り出す。
// 該当 OID が無ければ std::nullopt。
std::optional<std::vector<uint8_t>>
find_sgx_extension_octet(X509* pck_leaf, const char* oid);

// Quote から PPID(16 バイト)を抽出する。内部で必ずチェーン検証を実施する。
// 取り出せない場合は TeeAnchorError。
std::vector<uint8_t> extract_ppid_from_quote(const std::vector<uint8_t>& quote);

}  // namespace tee_anchor::sgx

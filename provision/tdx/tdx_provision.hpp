#pragma once
//
// TDX provision: TD Quote から PCK 証明書チェーンを取り出し、
// Intel SGX Root CA(ハードコード公開鍵)で検証した上で Chip ID(PPID) を抽出する処理。
//
// SGX とほぼ同じだが、TD Quote のバイナリ構造が異なる 2 点だけを TDX 用に扱う:
//
//   (1) Quote のフレーミングが version で変わる:
//        v4: Header(48) | TD report body(固定) | sig_len(u32) | sig_data
//        v5: Header(48) | body_type(u16) | body_size(u32) | body | sig_len(u32) | sig_data
//        → signature_data の開始オフセットが version/レポート版で変わる。
//   (2) PCK 証明書チェーンが二重にネストされる:
//        sig_data = sig(64) | attest_pub_key(64)
//                   | cert_data{ type=6 (QE_REPORT_CERTIFICATION_DATA):
//                        qe_report(384) | qe_report_sig(64) | qe_auth_data
//                        | cert_data{ type=5 (PCK_CERT_CHAIN): PCK PEM チェーン } }
//        → SGX(v3) は type=5 が sig_data 直下にあるのに対し、TDX は type=6 の中。
//
// PCK 証明書そのものは SGX/TDX で共通(プラットフォーム証明書)なので、チェーン検証と
// PPID 抽出は sgx::verify_pck_chain / sgx::find_sgx_extension_octet をそのまま再利用する。
//
#include <cstdint>
#include <vector>

#include "openssl_raii.hpp"

namespace tee_anchor::tdx {

// TD Quote(v4 / v5) の Certification Data に格納された PCK 証明書チェーン全体を取り出す。
// version を読んで signature_data の開始位置を決め、外側 type=6 → 内側 type=5 と
// 降りて PCK チェーン(PEM)を読む。type が想定外、または未知 version の場合は TeeAnchorError。
// 検証は行わない。sgx::verify_pck_chain() を別途呼ぶこと。
std::vector<X509Ptr>
extract_pck_chain_from_quote(const std::vector<uint8_t>& quote);

// TD Quote から PPID(16 バイト)を抽出する。内部で必ずチェーン検証を実施する
// (sgx::verify_pck_chain → sgx::find_sgx_extension_octet)。
// 取り出せない場合は TeeAnchorError。
std::vector<uint8_t> extract_ppid_from_quote(const std::vector<uint8_t>& quote);

}  // namespace tee_anchor::tdx

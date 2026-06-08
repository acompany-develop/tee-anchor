#pragma once
//
// SEV-SNP provision: Attestation Report と VCEK 証明書チェーンを入力に取り、
// (1) チェーン検証 + Report 署名検証 → (2) 検証通過後に CHIP_ID を抽出する。
//
// 方針:
//   - ベンダー検証 (ARK→ASK→VCEK チェーン / VCEK による Report 署名) は
//     AMD 製ツール snpguest に委譲する。SGX で同等処理を QvL に委ねるのと同じ
//     役割分担で、TEE Anchor は組織 endorsement + Chip ID binding に集中する。
//   - ただし信頼根 (ARK) は TEE Anchor 側でも既知値に pin する (SGX の Intel root
//     ハードコードと同じプロパティを保つため)。
//   - CHIP_ID の抽出自体は Report の固定オフセット 0x1A0 から自前で行う
//     (AMD SEV-SNP Firmware ABI Spec, Table 23。VERSION 2〜5 で不変)。
//
#include <cstdint>
#include <string>
#include <vector>

#include "openssl_raii.hpp"

namespace tee_anchor::snp {

// VCEK の hwID 拡張 OID (AMD SEV-SNP)。Report の CHIP_ID とのクロスチェック用。
inline constexpr const char* OID_AMD_SEV_HWID = "1.3.6.1.4.1.3704.1.4";

// Attestation Report (FW report) の固定長とオフセット。
//   AMD SEV-SNP Firmware ABI Specification, Table 23. ATTESTATION_REPORT Structure
inline constexpr size_t kReportLen        = 1184;   // 0x4A0
inline constexpr size_t kOffVersion       = 0x000;  // u32 LE
inline constexpr size_t kOffSigAlgo       = 0x034;  // u32 LE
inline constexpr size_t kOffChipId        = 0x1A0;  // 64 bytes
inline constexpr size_t kChipIdLen        = 64;
inline constexpr size_t kOffSignedEnd     = 0x2A0;  // 署名対象は [0x0, 0x2A0)

// snpguest を使った検証 + CHIP_ID 抽出のまとめ。
struct SnpVerifyResult {
    std::vector<uint8_t> chip_id;     // Report 0x1A0 から抽出した 64B
    uint32_t             version;     // Report VERSION
    const char*          generation;  // pin にマッチした ARK 世代 ("Milan" 等)
    X509Ptr              vcek;         // VCEK leaf (endorsement の Subject pubkey 供給源)
};

// Report のヘッダを検証する (長さ・VERSION が既知 2〜5・SIGNATURE_ALGO が
// ECDSA-P384/SHA-384 か)。不正なら TeeAnchorError。
void validate_report_header(const std::vector<uint8_t>& report);

// 検証済み Report から CHIP_ID(64B, offset 0x1A0) を抽出する。
// all-zero (MaskChipId=1 で chip id がマスクされている) の場合は TeeAnchorError。
std::vector<uint8_t> extract_chip_id_from_report(const std::vector<uint8_t>& report);

// certs_dir 内の ark.pem を読み、その公開鍵が既知 ARK のいずれかに pin 一致するかを
// 照合する。一致した世代名を返す。不一致なら TeeAnchorError。
const char* verify_ark_pin(const std::string& certs_dir);

// snpguest verify certs / verify attestation を subprocess で実行する。
// snpguest 実行ファイルは snpguest_bin で与える (空なら PATH から探索)。
// 検証失敗時は TeeAnchorError。
void run_snpguest_verify(const std::string& snpguest_bin,
                         const std::string& certs_dir,
                         const std::string& report_path);

// 上記を束ねた provision 用の入口:
//   1. Report ヘッダ検証
//   2. ARK pin 照合
//   3. snpguest による チェーン検証 + Report 署名検証
//   4. CHIP_ID 抽出 + VCEK leaf ロード
// 検証がすべて通った場合のみ SnpVerifyResult を返す。
SnpVerifyResult
verify_and_extract(const std::string& report_path,
                   const std::string& certs_dir,
                   const std::string& snpguest_bin);

}  // namespace tee_anchor::snp

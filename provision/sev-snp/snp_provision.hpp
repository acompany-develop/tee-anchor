#pragma once
//
// SEV-SNP provision: Attestation Report と VCEK 証明書チェーンを入力に取り、
// (1) チェーン検証 + Report 署名検証 → (2) 検証通過後に CHIP_ID を抽出する。
//
// 方針:
//   - ベンダー検証 (ARK→ASK→VCEK チェーン / VCEK による Report 署名) を、
//     他 TEE 経路 (SGX の PCK チェーン検証, CCA の ES384 検証) と同じく
//     OpenSSL で自前実装する。外部ツール snpguest への subprocess 依存は廃止。
//   - 信頼根 (ARK) は TEE Anchor 側で既知値に pin する (SGX の Intel root
//     ハードコードと同じプロパティ)。pin した ARK を X509_STORE の信頼アンカーに
//     据え、ARK→ASK→VCEK を X509_verify_cert でチェーン検証する。
//   - Report 署名は VCEK 公開鍵 (EC P-384) で ECDSA-P384/SHA-384 を検証する。
//     署名対象は Report の先頭 [0x0, 0x2A0) バイト。
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

// SIGNATURE フィールド (Table 119)。R, S はそれぞれ 72 バイト幅の
// リトルエンディアン整数 (P-384 なので有効桁は下位 48 バイト、上位は 0 埋め)。
inline constexpr size_t kOffSignature     = 0x2A0;  // R が始まるオフセット
inline constexpr size_t kEcdsaCompLen     = 72;     // R / S 各フィールド長

// チェーン検証 + Report 署名検証 + CHIP_ID 抽出のまとめ。
struct SnpVerifyResult {
    std::vector<uint8_t> chip_id;     // Report 0x1A0 から抽出した 64B
    uint32_t             version;     // Report VERSION
    const char*          generation;  // pin にマッチした ARK 世代 ("Milan" 等)
    X509Ptr              vcek;         // VCEK leaf (endorsement の Subject pubkey 供給源)
};

// 検証済み VCEK チェーン (pin した ARK 世代 + leaf)。
struct SnpChain {
    X509Ptr     vcek;        // 検証済み VCEK leaf
    const char* generation;  // pin にマッチした ARK 世代
};

// Report のヘッダを検証する (長さ・VERSION が既知 2〜5・SIGNATURE_ALGO が
// ECDSA-P384/SHA-384 か)。不正なら TeeAnchorError。
void validate_report_header(const std::vector<uint8_t>& report);

// 検証済み Report から CHIP_ID(64B, offset 0x1A0) を抽出する。
// all-zero (MaskChipId=1 で chip id がマスクされている) の場合は TeeAnchorError。
std::vector<uint8_t> extract_chip_id_from_report(const std::vector<uint8_t>& report);

// certs_dir 内の ark.pem / ask.pem / vcek.pem を読み、
//   1. ARK 公開鍵が既知 AMD root のいずれかに pin 一致するか照合し、
//   2. pin した ARK を信頼アンカーに ARK→ASK→VCEK を X509_verify_cert で検証する。
// 検証通過時は VCEK leaf と pin にマッチした世代名を返す。失敗なら TeeAnchorError。
SnpChain verify_vcek_chain(const std::string& certs_dir);

// 検証済み VCEK の公開鍵 (EC P-384) で Report 署名を検証する。
// 署名対象は report[0, 0x2A0)、署名は SIGNATURE フィールドの R||S (各 72B LE)。
// 署名が一致しない/鍵種が不正なら TeeAnchorError。
void verify_report_signature(const std::vector<uint8_t>& report, X509* vcek);

// 上記を束ねた入口:
//   1. Report ヘッダ検証
//   2. ARK pin 照合 + ARK→ASK→VCEK チェーン検証 (verify_vcek_chain)
//   3. VCEK による Report 署名検証 (verify_report_signature)
//   4. CHIP_ID 抽出 (+ VCEK hwID 拡張とのクロスチェック)
// 検証がすべて通った場合のみ SnpVerifyResult を返す。
SnpVerifyResult
verify_and_extract(const std::string& report_path,
                   const std::string& certs_dir);

}  // namespace tee_anchor::snp

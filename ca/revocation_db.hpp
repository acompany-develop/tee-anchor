#pragma once
//
// 組織 CA が保持する失効記録 (revocation DB)。
//
// シンプルな flat text 形式 (依存ライブラリ追加なし):
//
//   # TEE Anchor revocation database (v1)
//   crl-number 3
//   <serial-hex> <YYYYMMDDHHMMSSZ> [reason-name]
//   ...
//
// - serial-hex: 大文字小文字不問、空白なし
// - revocation_date: GeneralizedTime 文字列 (UTC, 15 文字)
// - reason: OpenSSL の reason 名 (unspecified / keyCompromise / cACompromise /
//   affiliationChanged / superseded / cessationOfOperation /
//   certificateHold / privilegeWithdrawn / aACompromise) または空
// - 既定パスは ca.crt と同じディレクトリの revocations.txt
//
#include <cstdint>
#include <string>
#include <vector>

namespace tee_anchor::ca {

struct RevocationEntry {
    std::string serial_hex;       // 小文字 hex, no 0x
    std::string revocation_date;  // GeneralizedTime "YYYYMMDDHHMMSSZ"
    std::string reason;           // 空可
};

struct RevocationDb {
    uint64_t crl_number = 0;
    std::vector<RevocationEntry> entries;
};

// ca-cert の絶対/相対パスから、同じディレクトリの revocations.txt を導く。
std::string default_db_path(const std::string& ca_cert_path);

// ファイルが無ければ空の DB を返す。フォーマット異常時は TeeAnchorError。
RevocationDb load_revocation_db(const std::string& path);

// アトミック書き出し (tmp 経由で rename)。失敗時は TeeAnchorError。
void save_revocation_db(const std::string& path, const RevocationDb& db);

}  // namespace tee_anchor::ca

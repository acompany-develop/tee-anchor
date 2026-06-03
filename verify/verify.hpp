#pragma once
//
// `tee-anchor verify` サブコマンド：
//   Quote + 組織エンドースメント証明書 + 組織 CA 証明書 を入力に取り、
//   PCK chain 検証 → 組織 chain 検証 → Chip ID bit-for-bit 照合 を行う。
//
// exit code は design.md 準拠:
//   0   全検証成功
//   20  PCK chain 検証失敗
//   21  組織 chain 検証失敗
//   22  Chip ID 不一致 (= Proxy attack 検出)
//   24  組織 CRL により endorsement が失効していた
//   30  入出力 / 内部エラー
//
// Intel 側 CRL は QvL に委譲。組織側 CRL は --crl で任意指定。
//
#include <string>

namespace tee_anchor::verify {

struct VerifyArgs {
    std::string quote_path;       // --quote
    std::string org_cert_path;    // --org-cert
    std::string org_ca_path;      // --org-ca
    std::string crl_path;         // --crl (任意。指定時は CRL チェック有効)
    std::string tee_type = "sgx"; // --tee-type (Phase 1 では sgx のみ)
};

// 戻り値は exit code (0/20/21/22/30)。例外は内部で全て exit code に変換する。
int run_verify(const VerifyArgs& args);

// argv は `verify` 以降の引数列。
int cli_verify(int argc, char** argv);

}  // namespace tee_anchor::verify

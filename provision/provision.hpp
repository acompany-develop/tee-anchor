#pragma once
//
// `tee-anchor provision` サブコマンド：Quote と組織 CA から
// 組織エンドースメント証明書 (ChipIdBinding 拡張付き) を発行する。
//
#include <string>

namespace tee_anchor::provision {

struct ProvisionArgs {
    std::string quote_path;          // --quote
    std::string ca_key_path;         // --ca-key
    std::string ca_cert_path;        // --ca-cert
    std::string out_path;            // --out
    std::string subject;             // --subject (省略時は PPID から自動生成)
    int         validity_days = 365; // --validity-days
    std::string tee_type = "sgx";    // --tee-type (Phase 1 では sgx のみ)
};

void run_provision(const ProvisionArgs& args);
int  cli_provision(int argc, char** argv);

}  // namespace tee_anchor::provision

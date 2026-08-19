#pragma once
//
// `tee-anchor provision` サブコマンド：Quote と組織 CA から
// 組織エンドースメント証明書 (ChipIdBinding 拡張付き) を発行する。
//
#include <string>

namespace tee_anchor::provision {

struct ProvisionArgs {
    // Attestation Report (AR) の入力パス。TEE ごとに呼称は異なる
    // (SGX/TDX: Quote / SEV-SNP: Report / CCA: Token) が、いずれも AR そのもの
    // であるため CLI オプションは --report に統一する。
    std::string report_path;         // --report (全 tee-type 共通)

    // SEV-SNP 用の追加入力 (AR とは別に TEE ベンダ証明書が別添となるため)
    std::string certs_dir;           // --certs  (tee-type=snp; ark.pem/ask.pem/vcek.pem)

    // 共通
    std::string ca_key_path;         // --ca-key
    std::string ca_cert_path;        // --ca-cert
    std::string out_path;            // --out
    std::string subject;             // --subject (省略時は Chip ID から自動生成)
    int         validity_days = 365; // --validity-days
    std::string tee_type = "sgx";    // --tee-type (sgx / tdx / snp / cca)
};

void run_provision(const ProvisionArgs& args);
int  cli_provision(int argc, char** argv);

}  // namespace tee_anchor::provision

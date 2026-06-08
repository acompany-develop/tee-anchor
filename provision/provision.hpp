#pragma once
//
// `tee-anchor provision` サブコマンド：Quote と組織 CA から
// 組織エンドースメント証明書 (ChipIdBinding 拡張付き) を発行する。
//
#include <string>

namespace tee_anchor::provision {

struct ProvisionArgs {
    // SGX 用入力
    std::string quote_path;          // --quote (tee-type=sgx)

    // SEV-SNP 用入力
    std::string report_path;         // --report (tee-type=snp)
    std::string certs_dir;           // --certs  (tee-type=snp; ark.pem/ask.pem/vcek.pem)
    std::string snpguest_bin;        // --snpguest (省略時は PATH から探索)

    // 共通
    std::string ca_key_path;         // --ca-key
    std::string ca_cert_path;        // --ca-cert
    std::string out_path;            // --out
    std::string subject;             // --subject (省略時は Chip ID から自動生成)
    int         validity_days = 365; // --validity-days
    std::string tee_type = "sgx";    // --tee-type (sgx / snp)
};

void run_provision(const ProvisionArgs& args);
int  cli_provision(int argc, char** argv);

}  // namespace tee_anchor::provision

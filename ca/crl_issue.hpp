#pragma once
//
// `tee-anchor crl-issue` サブコマンド：
//   revocation DB の内容から X.509 CRL を組み立てて組織 CA で署名・PEM 出力する。
//
//   - CRL Number は DB の crl-number を発行時にインクリメントして使う。
//   - thisUpdate = now, nextUpdate = now + validity-days
//   - AuthorityKeyIdentifier 拡張で CA の SKI を埋める。
//   - 各 revoked entry には Reason 拡張 (DB に reason が指定されている場合のみ) を付与。
//
#include <string>

namespace tee_anchor::ca {

struct CrlIssueArgs {
    std::string ca_key_path;   // --ca-key
    std::string ca_cert_path;  // --ca-cert
    std::string out_path;      // --out
    int         validity_days = 7;
    std::string db_path;       // 省略時は ca.crt と同ディレクトリの revocations.txt
};

void run_crl_issue(const CrlIssueArgs& args);
int  cli_crl_issue(int argc, char** argv);

}  // namespace tee_anchor::ca

#pragma once
//
// `tee-anchor revoke` サブコマンド：
//   組織 CA が発行した endorsement 証明書を失効リストに追加する。
//   CRL ファイル自体はここでは出さず、後で `tee-anchor crl-issue` でまとめて発行する。
//
#include <string>

namespace tee_anchor::ca {

struct RevokeArgs {
    std::string ca_cert_path;   // --ca-cert
    std::string cert_path;      // --cert (失効させる endorsement 証明書)
    std::string reason;         // --reason (省略可。空 = reason 拡張無し)
    std::string db_path;        // --db (省略時は ca.crt と同ディレクトリの revocations.txt)
};

void run_revoke(const RevokeArgs& args);
int  cli_revoke(int argc, char** argv);

}  // namespace tee_anchor::ca

#pragma once
//
// `tee-anchor ca-init` サブコマンド：組織 Root CA を新規発行する。
//
//   - 鍵: ECDSA（曲線は --curve、既定 P-384）
//   - 自己署名証明書: BasicConstraints CA:TRUE (pathLenConstraint 無し),
//     KeyUsage digitalSignature/keyCertSign/cRLSign, SubjectKeyIdentifier
//   - 出力: <out_dir>/ca.key (0600) と <out_dir>/ca.crt (0644)
//
#include <string>

namespace tee_anchor::ca {

struct CaInitArgs {
    std::string out_dir;
    std::string subject = "CN=TEE Anchor Org CA";
    int         validity_days = 3650;
    std::string curve = "P-384";
    bool        force = false;
};

// 純粋なロジック層。テストや組み込み呼び出し用。例外で失敗を通知する。
void run_ca_init(const CaInitArgs& args);

// CLI 層: argv は `ca-init` 以降の引数列。戻り値はプロセス exit code。
int cli_ca_init(int argc, char** argv);

}  // namespace tee_anchor::ca

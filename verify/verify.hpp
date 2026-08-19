#pragma once
//
// `tee-anchor verify` サブコマンド：
//   attestation 証拠 + 組織エンドースメント証明書 + 組織 CA 証明書 を入力に取り、
//   ベンダー証拠検証 → 組織 chain 検証 → Chip ID bit-for-bit 照合 を行う。
//
//   SGX: 証拠 = Quote。PCK chain を Intel root pubkey で検証し PPID を抽出。
//   TDX: 証拠 = TD Quote。SGX と同じ(チェーン検証/PPID 抽出は共通)。TD Quote の
//        v4/v5 フレーミングと二重ネスト Cert Data のパースだけが TDX 固有。
//   SNP: 証拠 = Report + VCEK チェーン。ARK pin + 自前の ARK→ASK→VCEK チェーン /
//        VCEK による Report 署名検証で CHIP_ID を抽出。
//   CCA: 証拠 = CCA token。CPAK pin で Platform Token(COSE_Sign1/ES384)を検証し
//        instance-id を抽出。(2)(3) は他 TEE と共通。
//
// exit code は design.md 準拠:
//   0   全検証成功
//   20  ベンダー証拠検証失敗 (SGX: PCK chain / SNP: VCEK chain or Report 署名)
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
    // Attestation Report (AR) の入力パス。TEE ごとに呼称は異なる
    // (SGX/TDX: Quote / SEV-SNP: Report / CCA: Token) が、いずれも AR そのもの
    // であるため CLI オプションは --report に統一する。
    std::string report_path;      // --report (全 tee-type 共通)

    // SEV-SNP 用の追加証拠 (AR とは別に TEE ベンダ証明書が別添となるため)
    std::string certs_dir;        // --certs  (tee-type=snp; ark.pem/ask.pem/vcek.pem)

    // 共通
    std::string org_cert_path;    // --org-cert
    std::string org_ca_path;      // --org-ca
    std::string crl_path;         // --crl (任意。指定時は CRL チェック有効)
    std::string tee_type = "sgx"; // --tee-type (sgx / tdx / snp / cca)
};

// 戻り値は exit code (0/20/21/22/30)。例外は内部で全て exit code に変換する。
int run_verify(const VerifyArgs& args);

// argv は `verify` 以降の引数列。
int cli_verify(int argc, char** argv);

}  // namespace tee_anchor::verify

//
// tee_anchor.cpp — 単一バイナリのエントリポイント。
//
//   tee-anchor <subcommand> [args...]
//
// Phase 1 のサブコマンド:
//   ca-init    : 組織 Root CA を新規発行
//   provision  : Quote から組織エンドースメント証明書を発行
//   verify     : (未実装、Phase 1 後半で実装)
//
#include <cstdio>
#include <cstring>
#include <string>

#include "ca/ca_init.hpp"
#include "ca/crl_issue.hpp"
#include "ca/revoke.hpp"
#include "provision/provision.hpp"
#include "verify/verify.hpp"

namespace {

void print_usage() {
    std::printf(
        "Usage: tee-anchor <subcommand> [args...]\n"
        "\n"
        "Subcommands:\n"
        "  ca-init     Generate organization Root CA (key + self-signed cert)\n"
        "  provision   Issue an organization endorsement cert from a Quote\n"
        "  revoke      Mark an endorsement cert as revoked (append to revocation DB)\n"
        "  crl-issue   Publish a CRL from the revocation DB\n"
        "  verify      Verify a Quote + endorsement cert against an org CA (optionally with CRL)\n"
        "\n"
        "Run 'tee-anchor <subcommand> --help' for subcommand-specific options.\n");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }
    const std::string sub = argv[1];
    // 残り引数 (サブコマンド以降) を渡す
    const int   sub_argc = argc - 2;
    char* const* sub_argv = (argc > 2) ? &argv[2] : argv + argc;  // 空配列代用

    if (sub == "ca-init") {
        return tee_anchor::ca::cli_ca_init(sub_argc, const_cast<char**>(sub_argv));
    }
    if (sub == "provision") {
        return tee_anchor::provision::cli_provision(sub_argc, const_cast<char**>(sub_argv));
    }
    if (sub == "revoke") {
        return tee_anchor::ca::cli_revoke(sub_argc, const_cast<char**>(sub_argv));
    }
    if (sub == "crl-issue") {
        return tee_anchor::ca::cli_crl_issue(sub_argc, const_cast<char**>(sub_argv));
    }
    if (sub == "verify") {
        return tee_anchor::verify::cli_verify(sub_argc, const_cast<char**>(sub_argv));
    }
    if (sub == "-h" || sub == "--help" || sub == "help") {
        print_usage();
        return 0;
    }
    std::fprintf(stderr, "[error] unknown subcommand: %s\n", sub.c_str());
    print_usage();
    return 1;
}

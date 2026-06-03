//
// ca_init.cpp — `tee-anchor ca-init` の実装。
//
#include "ca_init.hpp"

#include <cstdio>
#include <stdexcept>
#include <string>

#include "error.hpp"
#include "io.hpp"
#include "openssl_raii.hpp"
#include "pki_util.hpp"

namespace tee_anchor::ca {

void run_ca_init(const CaInitArgs& args) {
    if (args.out_dir.empty()) {
        throw TeeAnchorError("--out-dir is required");
    }
    if (args.validity_days <= 0) {
        throw TeeAnchorError("--validity-days must be positive");
    }

    const std::string key_path = args.out_dir + "/ca.key";
    const std::string crt_path = args.out_dir + "/ca.crt";

    if (!args.force) {
        if (path_exists(key_path)) {
            throw TeeAnchorError("already exists: " + key_path +
                                 " (use --force to overwrite)");
        }
        if (path_exists(crt_path)) {
            throw TeeAnchorError("already exists: " + crt_path +
                                 " (use --force to overwrite)");
        }
    }

    // 1. 鍵ペア生成
    EvpPkeyPtr pkey = pki::gen_ec_key(args.curve);

    // 2. 証明書骨格
    X509Ptr cert(X509_new());
    if (!cert) throw_openssl_error("X509_new");
    if (X509_set_version(cert.get(), 2) != 1) {  // v3
        throw_openssl_error("X509_set_version");
    }

    Asn1IntPtr sn = pki::random_serial();
    if (X509_set_serialNumber(cert.get(), sn.get()) != 1) {
        throw_openssl_error("X509_set_serialNumber");
    }

    if (!X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0)) {
        throw_openssl_error("X509_gmtime_adj (notBefore)");
    }
    if (!X509_gmtime_adj(X509_getm_notAfter(cert.get()),
                         static_cast<long>(args.validity_days) * 86400L)) {
        throw_openssl_error("X509_gmtime_adj (notAfter)");
    }

    // Subject == Issuer (自己署名)
    X509NamePtr name = pki::parse_dn(args.subject);
    if (X509_set_subject_name(cert.get(), name.get()) != 1) {
        throw_openssl_error("X509_set_subject_name");
    }
    if (X509_set_issuer_name(cert.get(), name.get()) != 1) {
        throw_openssl_error("X509_set_issuer_name");
    }

    if (X509_set_pubkey(cert.get(), pkey.get()) != 1) {
        throw_openssl_error("X509_set_pubkey");
    }

    // 3. 拡張
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);
    // pathLenConstraint は付けない: Phase 2 で intermediate を挟む際に
    // root cert を再発行せずに済むようにするため (design.md「PKI 階層」参照)。
    pki::add_v3_ext(cert.get(), &ctx, NID_basic_constraints,
                    "critical,CA:TRUE");
    pki::add_v3_ext(cert.get(), &ctx, NID_key_usage,
                    "critical,digitalSignature,keyCertSign,cRLSign");
    pki::add_v3_ext(cert.get(), &ctx, NID_subject_key_identifier, "hash");

    // 4. 自己署名
    if (X509_sign(cert.get(), pkey.get(),
                  pki::sig_md_for_curve(args.curve)) == 0) {
        throw_openssl_error("X509_sign");
    }

    // 5. ファイル出力 (key を先に厳格パーミッションで書く)
    auto key_pem = pki::pem_private_key(pkey.get());
    write_file(key_path, key_pem.data(), key_pem.size(), 0600);

    auto crt_pem = pki::pem_cert(cert.get());
    write_file(crt_path, crt_pem.data(), crt_pem.size(), 0644);

    std::printf("CA initialized:\n");
    std::printf("  subject       : %s\n", args.subject.c_str());
    std::printf("  curve         : %s\n", args.curve.c_str());
    std::printf("  validity      : %d days\n", args.validity_days);
    std::printf("  private key   : %s (mode 0600)\n", key_path.c_str());
    std::printf("  certificate   : %s (mode 0644)\n", crt_path.c_str());
}

int cli_ca_init(int argc, char** argv) {
    CaInitArgs args;
    auto need_value = [&](int& i, const char* opt) -> const char* {
        if (i + 1 >= argc) {
            throw TeeAnchorError(std::string(opt) + " requires a value");
        }
        return argv[++i];
    };

    try {
        for (int i = 0; i < argc; ++i) {
            std::string a = argv[i];
            if      (a == "--out-dir")       args.out_dir       = need_value(i, "--out-dir");
            else if (a == "--subject")       args.subject       = need_value(i, "--subject");
            else if (a == "--validity-days") args.validity_days = std::stoi(need_value(i, "--validity-days"));
            else if (a == "--curve")         args.curve         = need_value(i, "--curve");
            else if (a == "--force")         args.force         = true;
            else if (a == "-h" || a == "--help") {
                std::printf(
                    "Usage: tee-anchor ca-init --out-dir <dir> [options]\n"
                    "\n"
                    "Options:\n"
                    "  --out-dir <dir>        (required) output directory for ca.key / ca.crt\n"
                    "  --subject <DN>         CA subject DN (default: CN=TEE Anchor Org CA)\n"
                    "  --validity-days <N>    CA validity in days (default: 3650)\n"
                    "  --curve <name>         EC curve: P-256|P-384|P-521 (default: P-384)\n"
                    "  --force                overwrite existing ca.key / ca.crt\n");
                return 0;
            }
            else {
                throw TeeAnchorError("unknown argument: " + a);
            }
        }
        run_ca_init(args);
        return 0;
    } catch (const TeeAnchorError& e) {
        std::fprintf(stderr, "[error] ca-init: %s\n", e.what());
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[error] ca-init: %s\n", e.what());
        return 2;
    }
}

}  // namespace tee_anchor::ca

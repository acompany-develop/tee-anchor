//
// provision.cpp — `tee-anchor provision` の実装。
//
#include "provision.hpp"

#include <cstdio>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "error.hpp"
#include "hex.hpp"
#include "io.hpp"
#include "openssl_raii.hpp"
#include "pki_util.hpp"

#include "binding/chip_id_binding.hpp"
#include "sev-snp/snp_provision.hpp"
#include "sgx/sgx_provision.hpp"

namespace tee_anchor::provision {

namespace {

// ----- TEE 別 chip ID 抽出 -------------------------------------------------
struct ChipIdResult {
    std::vector<uint8_t> chip_id;   // PPID 等
    uint8_t              tee_type;  // binding::kTeeTypeSgx 等
    X509Ptr              leaf;      // PCK leaf (Subject pubkey の供給源)
};

ChipIdResult extract_chip_id_for_sgx(const std::string& quote_path) {
    auto quote = read_file(quote_path);
    auto chain = sgx::extract_pck_chain_from_quote(quote);
    X509* leaf_ptr = sgx::verify_pck_chain(chain);

    auto ppid = sgx::find_sgx_extension_octet(leaf_ptr, sgx::OID_SGX_PPID);
    if (!ppid) {
        throw TeeAnchorError("PPID (OID " + std::string(sgx::OID_SGX_PPID) +
                             ") not found in PCK leaf");
    }

    bool all_zero = true;
    for (uint8_t b : *ppid) { if (b) { all_zero = false; break; } }
    if (all_zero) {
        // 暗号化/redacted PPID の可能性。Phase 1 では設計上 plaintext 前提のため警告。
        std::fprintf(stderr,
            "[warn] PPID is all-zero; PCK cert may carry an encrypted/redacted "
            "PPID. Proceeding, but the resulting endorsement may not bind a "
            "useful Chip ID.\n");
    }

    // leaf の所有権を chain から取り出す (X509Ptr に移し替え)。
    X509Ptr leaf_owned;
    for (auto& c : chain) {
        if (c.get() == leaf_ptr) { leaf_owned = std::move(c); break; }
    }
    return ChipIdResult{*ppid, binding::kTeeTypeSgx, std::move(leaf_owned)};
}

ChipIdResult extract_chip_id_for_snp(const ProvisionArgs& args) {
    // ベンダー検証 (チェーン + Report 署名) は snpguest に委譲し、信頼根 (ARK) は
    // TEE Anchor 側で pin する。検証通過後に Report の CHIP_ID を抽出する。
    snp::SnpVerifyResult r =
        snp::verify_and_extract(args.report_path, args.certs_dir, args.snpguest_bin);
    std::fprintf(stderr, "[info] SNP report verified (version %u, ARK=%s)\n",
                 r.version, r.generation);
    // SGX の PCK leaf と対称に、VCEK leaf の公開鍵を endorsement の Subject pubkey に使う。
    return ChipIdResult{std::move(r.chip_id), binding::kTeeTypeSevSnp, std::move(r.vcek)};
}

ChipIdResult extract_chip_id(const ProvisionArgs& args) {
    if (args.tee_type == "sgx") return extract_chip_id_for_sgx(args.quote_path);
    if (args.tee_type == "snp") return extract_chip_id_for_snp(args);
    if (args.tee_type == "tdx") {
        throw TeeAnchorError("--tee-type tdx is not implemented yet");
    }
    throw TeeAnchorError("unknown --tee-type: " + args.tee_type);
}

std::string auto_subject(const std::vector<uint8_t>& chip_id) {
    // 先頭 4 バイト分を hex で短縮 ID として使う (8 文字)
    const size_t n = chip_id.size() < 4 ? chip_id.size() : 4;
    return std::string("CN=tee-anchor-") + to_hex_lower(chip_id.data(), n);
}

}  // namespace

void run_provision(const ProvisionArgs& args) {
    // 1. 必須引数チェック
    auto require = [](const std::string& v, const char* name) {
        if (v.empty()) throw TeeAnchorError(std::string(name) + " is required");
    };
    // TEE 種別ごとに証拠の入力が異なる (SGX: Quote 単体 / SNP: Report + 証明書dir)。
    if (args.tee_type == "sgx") {
        require(args.quote_path, "--quote");
    } else if (args.tee_type == "snp") {
        require(args.report_path, "--report");
        require(args.certs_dir,   "--certs");
    }
    require(args.ca_key_path,  "--ca-key");
    require(args.ca_cert_path, "--ca-cert");
    require(args.out_path,     "--out");
    if (args.validity_days <= 0) {
        throw TeeAnchorError("--validity-days must be positive");
    }

    // 2. CA をロード
    EvpPkeyPtr ca_key  = pki::load_pem_private_key(args.ca_key_path);
    X509Ptr    ca_cert = pki::load_pem_cert(args.ca_cert_path);
    if (X509_check_private_key(ca_cert.get(), ca_key.get()) != 1) {
        throw TeeAnchorError("CA private key does not match CA certificate");
    }

    // 3. 証拠 -> ベンダー検証 -> Chip ID 抽出 (TEE 種別ごとに dispatch)
    auto chip = extract_chip_id(args);

    // 4. Endorsement cert 骨格
    X509Ptr endorsement(X509_new());
    if (!endorsement) throw_openssl_error("X509_new");
    if (X509_set_version(endorsement.get(), 2) != 1) {
        throw_openssl_error("X509_set_version");
    }

    Asn1IntPtr sn = pki::random_serial();
    if (X509_set_serialNumber(endorsement.get(), sn.get()) != 1) {
        throw_openssl_error("X509_set_serialNumber");
    }

    if (!X509_gmtime_adj(X509_getm_notBefore(endorsement.get()), 0)) {
        throw_openssl_error("X509_gmtime_adj (notBefore)");
    }
    if (!X509_gmtime_adj(X509_getm_notAfter(endorsement.get()),
                         static_cast<long>(args.validity_days) * 86400L)) {
        throw_openssl_error("X509_gmtime_adj (notAfter)");
    }

    // Issuer = CA の Subject
    if (X509_set_issuer_name(endorsement.get(),
                             X509_get_subject_name(ca_cert.get())) != 1) {
        throw_openssl_error("X509_set_issuer_name");
    }

    // Subject = ユーザ指定 or 自動 (PPID 先頭 4 バイト)
    const std::string subject_str = args.subject.empty()
        ? auto_subject(chip.chip_id) : args.subject;
    X509NamePtr subject = pki::parse_dn(subject_str);
    if (X509_set_subject_name(endorsement.get(), subject.get()) != 1) {
        throw_openssl_error("X509_set_subject_name");
    }

    // Subject Public Key = leaf 証明書の公開鍵
    //   SGX: PCK leaf / SNP: VCEK leaf。
    // 「この leaf 公開鍵を持つマシン = 組織管理下」という表明を素直に反映。
    EVP_PKEY* leaf_pub = X509_get0_pubkey(chip.leaf.get());
    if (!leaf_pub) throw_openssl_error("X509_get0_pubkey (leaf)");
    if (X509_set_pubkey(endorsement.get(), leaf_pub) != 1) {
        throw_openssl_error("X509_set_pubkey (endorsement)");
    }

    // 5. 拡張
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, /*issuer=*/ca_cert.get(),
                   /*subject=*/endorsement.get(),
                   nullptr, nullptr, 0);
    pki::add_v3_ext(endorsement.get(), &ctx, NID_basic_constraints,        "critical,CA:FALSE");
    pki::add_v3_ext(endorsement.get(), &ctx, NID_key_usage,                "critical,digitalSignature");
    pki::add_v3_ext(endorsement.get(), &ctx, NID_subject_key_identifier,   "hash");
    pki::add_v3_ext(endorsement.get(), &ctx, NID_authority_key_identifier, "keyid:always");

    // ChipIdBinding (Critical)
    auto binding_der = binding::encode_chip_id_binding(chip.tee_type, chip.chip_id);
    X509ExtPtr binding_ext = binding::make_chip_id_binding_extension(binding_der);
    if (X509_add_ext(endorsement.get(), binding_ext.get(), -1) != 1) {
        throw_openssl_error("X509_add_ext (ChipIdBinding)");
    }

    // 6. 組織 CA 鍵で署名
    if (X509_sign(endorsement.get(), ca_key.get(),
                  pki::digest_for_signing_key(ca_key.get())) == 0) {
        throw_openssl_error("X509_sign (endorsement)");
    }

    // 7. 出力
    auto pem = pki::pem_cert(endorsement.get());
    write_file(args.out_path, pem.data(), pem.size(), 0644);

    std::printf("Endorsement issued:\n");
    std::printf("  tee_type      : %s\n", args.tee_type.c_str());
    std::printf("  chip_id (hex) : %s\n", to_hex_lower(chip.chip_id).c_str());
    std::printf("  subject       : %s\n", subject_str.c_str());
    std::printf("  validity      : %d days\n", args.validity_days);
    std::printf("  output        : %s\n", args.out_path.c_str());
}

int cli_provision(int argc, char** argv) {
    ProvisionArgs args;
    auto need_value = [&](int& i, const char* opt) -> const char* {
        if (i + 1 >= argc) {
            throw TeeAnchorError(std::string(opt) + " requires a value");
        }
        return argv[++i];
    };

    try {
        for (int i = 0; i < argc; ++i) {
            std::string a = argv[i];
            if      (a == "--quote")         args.quote_path     = need_value(i, "--quote");
            else if (a == "--report")        args.report_path    = need_value(i, "--report");
            else if (a == "--certs")         args.certs_dir      = need_value(i, "--certs");
            else if (a == "--snpguest")      args.snpguest_bin   = need_value(i, "--snpguest");
            else if (a == "--ca-key")        args.ca_key_path    = need_value(i, "--ca-key");
            else if (a == "--ca-cert")       args.ca_cert_path   = need_value(i, "--ca-cert");
            else if (a == "--out")           args.out_path       = need_value(i, "--out");
            else if (a == "--subject")       args.subject        = need_value(i, "--subject");
            else if (a == "--validity-days") args.validity_days  = std::stoi(need_value(i, "--validity-days"));
            else if (a == "--tee-type")      args.tee_type       = need_value(i, "--tee-type");
            else if (a == "-h" || a == "--help") {
                std::printf(
                    "Usage:\n"
                    "  tee-anchor provision --tee-type sgx --quote <file> --ca-key <file> --ca-cert <file> --out <file> [options]\n"
                    "  tee-anchor provision --tee-type snp --report <file> --certs <dir> --ca-key <file> --ca-cert <file> --out <file> [options]\n"
                    "\n"
                    "Common options:\n"
                    "  --ca-key <file>        (required) organization CA private key (PEM)\n"
                    "  --ca-cert <file>       (required) organization CA certificate (PEM)\n"
                    "  --out <file>           (required) output endorsement cert (PEM)\n"
                    "  --subject <DN>         endorsement cert subject DN (default: auto from Chip ID)\n"
                    "  --validity-days <N>    endorsement validity in days (default: 365)\n"
                    "  --tee-type <sgx|snp>   TEE type (default: sgx)\n"
                    "\n"
                    "SGX options (--tee-type sgx):\n"
                    "  --quote <file>         (required) SGX Quote (binary, e.g. quote.dat)\n"
                    "\n"
                    "SEV-SNP options (--tee-type snp):\n"
                    "  --report <file>        (required) SNP attestation report (binary, report.bin)\n"
                    "  --certs <dir>          (required) dir with ark.pem/ask.pem/vcek.pem (from snpguest fetch)\n"
                    "  --snpguest <path>      snpguest binary used for chain/report verification\n"
                    "                         (default: looked up on PATH)\n");
                return 0;
            }
            else {
                throw TeeAnchorError("unknown argument: " + a);
            }
        }
        run_provision(args);
        return 0;
    } catch (const TeeAnchorError& e) {
        std::fprintf(stderr, "[error] provision: %s\n", e.what());
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[error] provision: %s\n", e.what());
        return 2;
    }
}

}  // namespace tee_anchor::provision

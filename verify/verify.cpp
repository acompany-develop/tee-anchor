//
// verify.cpp — `tee-anchor verify` の実装。
//
#include "verify.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "error.hpp"
#include "hex.hpp"
#include "io.hpp"
#include "openssl_raii.hpp"
#include "pki_util.hpp"

#include "binding/chip_id_binding.hpp"
#include "cca/cca_provision.hpp"
#include "sev-snp/snp_provision.hpp"
#include "sgx/sgx_provision.hpp"
#include "tdx/tdx_provision.hpp"

namespace tee_anchor::verify {

namespace {

constexpr int kExitOk          = 0;
constexpr int kExitEvidence    = 20;  // ベンダー証拠検証失敗 (SGX: PCK / SNP: VCEK・署名)
constexpr int kExitOrgFailed   = 21;
constexpr int kExitMismatch    = 22;
constexpr int kExitRevoked     = 24;
constexpr int kExitInternal    = 30;

// PCK 証明書チェーン(SGX/TDX 共通形式)を検証し、PPID を取り出す。
// チェーン検証(Intel SGX Root CA pin)と PPID 抽出は SGX/TDX で完全に同一。
std::vector<uint8_t> ppid_from_pck_chain(const std::vector<X509Ptr>& chain) {
    X509* leaf = sgx::verify_pck_chain(chain);
    auto ppid = sgx::find_sgx_extension_octet(leaf, sgx::OID_SGX_PPID);
    if (!ppid) {
        throw TeeAnchorError("PPID (OID " + std::string(sgx::OID_SGX_PPID) +
                             ") not found in PCK leaf");
    }
    return *ppid;
}

// attestation 証拠 (Quote / Report+VCEK) をベンダー検証し、Chip ID を取り出す。
// TEE 種別ごとに検証経路が異なるが、いずれも「検証通過後にだけ Chip ID を返す」。
// 検証失敗時は TeeAnchorError (呼び出し側で exit 20 に変換)。
std::vector<uint8_t> verify_evidence_and_extract_chip_id(const VerifyArgs& args) {
    if (args.tee_type == "sgx") {
        auto quote = read_file(args.quote_path);
        return ppid_from_pck_chain(sgx::extract_pck_chain_from_quote(quote));
    }
    if (args.tee_type == "tdx") {
        // SGX とほぼ同じ。差は TD Quote のフレーミング(v4/v5)と二重ネストした
        // Certification Data の降り方だけで、それは tdx::extract_pck_chain_from_quote が吸収する。
        auto quote = read_file(args.quote_path);
        return ppid_from_pck_chain(tdx::extract_pck_chain_from_quote(quote));
    }
    if (args.tee_type == "snp") {
        // provision と同じ検証経路を再利用 (ARK pin + snpguest verify certs/attestation)。
        // verify では VCEK leaf は不要なので chip_id のみ受け取る。
        snp::SnpVerifyResult r =
            snp::verify_and_extract(args.report_path, args.certs_dir, args.snpguest_bin);
        return std::move(r.chip_id);
    }
    if (args.tee_type == "cca") {
        // provision と同じ検証経路を再利用 (CPAK pin で COSE_Sign1/ES384 検証)。
        // verify では CPAK leaf は不要なので instance-id のみ受け取る。
        cca::CcaVerifyResult r = cca::verify_and_extract(args.token_path);
        return std::move(r.instance_id);
    }
    throw TeeAnchorError("unknown --tee-type: " + args.tee_type);
}

enum class OrgChainStatus { Ok, Revoked, OtherFail };

struct OrgChainResult {
    OrgChainStatus status;
    std::string    error_string;  // status != Ok のときに詳細
};

// 組織 endorsement cert を 組織 CA cert に対してチェーン検証する。
// ChipIdBinding が Critical で乗っているため、X509_V_FLAG_IGNORE_CRITICAL を立てる。
// crl が non-null なら trust store に登録して X509_V_FLAG_CRL_CHECK を有効化する。
OrgChainResult verify_org_chain(X509* org_cert, X509* org_ca, X509_CRL* crl) {
    X509StorePtr store(X509_STORE_new());
    if (!store) throw_openssl_error("X509_STORE_new");
    if (X509_STORE_add_cert(store.get(), org_ca) != 1) {
        throw_openssl_error("X509_STORE_add_cert (org_ca)");
    }

    unsigned long flags = X509_V_FLAG_IGNORE_CRITICAL;
    if (crl) {
        // ChipIdBinding が Critical でも通せるよう IGNORE_CRITICAL は付けたまま、
        // 組織 endorsement (= leaf) の CRL 照合を有効化する。
        // CRL_CHECK_ALL までは付けない (root CA 用 CRL は持たないため)。
        if (X509_STORE_add_crl(store.get(), crl) != 1) {
            throw_openssl_error("X509_STORE_add_crl");
        }
        flags |= X509_V_FLAG_CRL_CHECK;
    }
    X509_VERIFY_PARAM* param = X509_STORE_get0_param(store.get());
    if (!param) throw_openssl_error("X509_STORE_get0_param");
    if (X509_VERIFY_PARAM_set_flags(param, flags) != 1) {
        throw_openssl_error("X509_VERIFY_PARAM_set_flags");
    }

    X509StoreCtxPtr ctx(X509_STORE_CTX_new());
    if (!ctx) throw_openssl_error("X509_STORE_CTX_new");
    if (X509_STORE_CTX_init(ctx.get(), store.get(), org_cert, nullptr) != 1) {
        throw_openssl_error("X509_STORE_CTX_init");
    }

    if (X509_verify_cert(ctx.get()) == 1) {
        return {OrgChainStatus::Ok, ""};
    }
    const int err = X509_STORE_CTX_get_error(ctx.get());
    const std::string msg = X509_verify_cert_error_string(err);
    if (err == X509_V_ERR_CERT_REVOKED) {
        return {OrgChainStatus::Revoked, msg};
    }
    return {OrgChainStatus::OtherFail, msg};
}

uint8_t expected_tee_type(const std::string& s) {
    if (s == "sgx") return binding::kTeeTypeSgx;
    if (s == "tdx") return binding::kTeeTypeTdx;
    if (s == "snp") return binding::kTeeTypeSevSnp;
    if (s == "cca") return binding::kTeeTypeArmCca;
    throw TeeAnchorError("unknown --tee-type: " + s);
}

}  // namespace

int run_verify(const VerifyArgs& args) {
    // 引数チェック (CLI でも検査しているが念のため)
    auto require = [](const std::string& v, const char* name) {
        if (v.empty()) throw TeeAnchorError(std::string(name) + " is required");
    };
    try {
        require(args.org_cert_path, "--org-cert");
        require(args.org_ca_path,   "--org-ca");
        // TEE 種別ごとに証拠の入力が異なる (SGX/TDX: Quote / SNP: Report + 証明書dir / CCA: token)。
        if (args.tee_type == "sgx" || args.tee_type == "tdx") {
            require(args.quote_path, "--quote");
        } else if (args.tee_type == "snp") {
            require(args.report_path, "--report");
            require(args.certs_dir,   "--certs");
        } else if (args.tee_type == "cca") {
            require(args.token_path, "--token");
        } else {
            throw TeeAnchorError("unknown --tee-type: " + args.tee_type);
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[error] %s\n", e.what());
        return kExitInternal;
    }

    // 入力ロード (IO エラー)
    X509Ptr    org_cert, org_ca;
    X509CrlPtr org_crl;
    try {
        org_cert = pki::load_pem_cert(args.org_cert_path);
        org_ca   = pki::load_pem_cert(args.org_ca_path);
        if (!args.crl_path.empty()) {
            org_crl = pki::load_pem_crl(args.crl_path);
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[error] loading inputs: %s\n", e.what());
        return kExitInternal;
    }

    // (1) ベンダー証拠検証 + Chip ID 抽出 (TEE 種別ごとに dispatch)
    std::vector<uint8_t> evidence_chip_id;
    try {
        evidence_chip_id = verify_evidence_and_extract_chip_id(args);
    } catch (const std::exception& e) {
        std::fprintf(stderr,
            "[fail/20] attestation evidence verification failed: %s\n", e.what());
        return kExitEvidence;
    }

    // (2) 組織 endorsement chain 検証 (+ 任意で CRL)
    {
        OrgChainResult r;
        try {
            r = verify_org_chain(org_cert.get(), org_ca.get(), org_crl.get());
        } catch (const std::exception& e) {
            std::fprintf(stderr,
                "[error] org chain verification setup failed: %s\n", e.what());
            return kExitInternal;
        }
        switch (r.status) {
            case OrgChainStatus::Ok:
                break;
            case OrgChainStatus::Revoked:
                std::fprintf(stderr,
                    "[fail/24] Endorsement certificate has been revoked by the organization CRL "
                    "(%s).\n", r.error_string.c_str());
                return kExitRevoked;
            case OrgChainStatus::OtherFail:
                std::fprintf(stderr,
                    "[fail/21] Organization chain verification failed: %s\n",
                    r.error_string.c_str());
                return kExitOrgFailed;
        }
    }

    // (3) ChipIdBinding 抽出 + 一致確認
    try {
        binding::ChipIdBinding chip = binding::extract_chip_id_binding(org_cert.get());

        const uint8_t expected = expected_tee_type(args.tee_type);
        if (chip.tee_type != expected) {
            std::fprintf(stderr,
                "[fail/22] teeType mismatch: endorsement claims %s(%u), expected %s(%u)\n",
                binding::tee_type_name(chip.tee_type), chip.tee_type,
                binding::tee_type_name(expected), expected);
            return kExitMismatch;
        }

        if (chip.chip_id.size() != evidence_chip_id.size() ||
            !std::equal(chip.chip_id.begin(), chip.chip_id.end(),
                        evidence_chip_id.begin())) {
            std::fprintf(stderr, "[fail/22] Chip ID mismatch:\n");
            std::fprintf(stderr, "  from evidence    : %s (%zu bytes)\n",
                         to_hex_lower(evidence_chip_id).c_str(), evidence_chip_id.size());
            std::fprintf(stderr, "  from endorsement : %s (%zu bytes)\n",
                         to_hex_lower(chip.chip_id).c_str(), chip.chip_id.size());
            return kExitMismatch;
        }

        std::printf("verify: OK\n");
        std::printf("  tee_type       : %s (%u)\n",
                    binding::tee_type_name(chip.tee_type), chip.tee_type);
        std::printf("  chip_id (hex)  : %s\n", to_hex_lower(evidence_chip_id).c_str());
        std::printf("  endorsement DN : ");
        {
            char buf[256];
            X509_NAME_oneline(X509_get_subject_name(org_cert.get()),
                              buf, sizeof(buf));
            std::printf("%s\n", buf);
        }
        std::printf("  ca DN          : ");
        {
            char buf[256];
            X509_NAME_oneline(X509_get_subject_name(org_ca.get()),
                              buf, sizeof(buf));
            std::printf("%s\n", buf);
        }
        std::printf("  issued_at      : %s\n", chip.issued_at.c_str());
        return kExitOk;
    } catch (const std::exception& e) {
        std::fprintf(stderr,
            "[fail/22] ChipIdBinding processing failed: %s\n", e.what());
        return kExitMismatch;
    }
}

int cli_verify(int argc, char** argv) {
    VerifyArgs args;
    auto need_value = [&](int& i, const char* opt) -> const char* {
        if (i + 1 >= argc) {
            throw TeeAnchorError(std::string(opt) + " requires a value");
        }
        return argv[++i];
    };

    try {
        for (int i = 0; i < argc; ++i) {
            std::string a = argv[i];
            if      (a == "--quote")    args.quote_path    = need_value(i, "--quote");
            else if (a == "--token")    args.token_path    = need_value(i, "--token");
            else if (a == "--report")   args.report_path   = need_value(i, "--report");
            else if (a == "--certs")    args.certs_dir     = need_value(i, "--certs");
            else if (a == "--snpguest") args.snpguest_bin  = need_value(i, "--snpguest");
            else if (a == "--org-cert") args.org_cert_path = need_value(i, "--org-cert");
            else if (a == "--org-ca")   args.org_ca_path   = need_value(i, "--org-ca");
            else if (a == "--crl")      args.crl_path      = need_value(i, "--crl");
            else if (a == "--tee-type") args.tee_type      = need_value(i, "--tee-type");
            else if (a == "-h" || a == "--help") {
                std::printf(
                    "Usage:\n"
                    "  tee-anchor verify --tee-type sgx --quote <file> --org-cert <file> --org-ca <file> [options]\n"
                    "  tee-anchor verify --tee-type tdx --quote <file> --org-cert <file> --org-ca <file> [options]\n"
                    "  tee-anchor verify --tee-type snp --report <file> --certs <dir> --org-cert <file> --org-ca <file> [options]\n"
                    "  tee-anchor verify --tee-type cca --token <file> --org-cert <file> --org-ca <file> [options]\n"
                    "\n"
                    "Common options:\n"
                    "  --org-cert <file>      (required) organization endorsement cert (PEM)\n"
                    "  --org-ca <file>        (required) organization root CA cert (PEM, trust anchor)\n"
                    "  --crl <file>           organization CRL (PEM). When given, endorsement is also\n"
                    "                         checked against this CRL (exit 24 if revoked).\n"
                    "  --tee-type <sgx|tdx|snp|cca>  TEE type (default: sgx)\n"
                    "\n"
                    "SGX/TDX options (--tee-type sgx | tdx):\n"
                    "  --quote <file>         (required) SGX Quote or TD Quote (binary, quote.dat)\n"
                    "\n"
                    "SEV-SNP options (--tee-type snp):\n"
                    "  --report <file>        (required) SNP attestation report (binary, report.bin)\n"
                    "  --certs <dir>          (required) dir with ark.pem/ask.pem/vcek.pem (from snpguest fetch)\n"
                    "  --snpguest <path>      snpguest binary used for chain/report verification\n"
                    "                         (default: looked up on PATH)\n"
                    "\n"
                    "Arm CCA options (--tee-type cca):\n"
                    "  --token <file>         (required) CCA attestation token (CBOR, cca-token.cbor)\n"
                    "\n"
                    "Exit codes:\n"
                    "  0   all checks passed\n"
                    " 20   attestation evidence verification failed (SGX/TDX: PCK chain / SNP: VCEK chain or report signature / CCA: CPAK or COSE signature)\n"
                    " 21   organization endorsement chain verification failed\n"
                    " 22   Chip ID mismatch (= proxy attack detected)\n"
                    " 24   endorsement revoked by organization CRL\n"
                    " 30   I/O or internal error\n");
                return 0;
            }
            else {
                throw TeeAnchorError("unknown argument: " + a);
            }
        }
    } catch (const TeeAnchorError& e) {
        std::fprintf(stderr, "[error] verify: %s\n", e.what());
        return kExitInternal;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[error] verify: %s\n", e.what());
        return kExitInternal;
    }

    return run_verify(args);
}

}  // namespace tee_anchor::verify

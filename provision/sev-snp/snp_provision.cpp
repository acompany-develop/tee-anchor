//
// snp_provision.cpp
//
// Phase 2 / SEV-SNP:
//   Attestation Report + VCEK 証明書チェーンを入力に取り、
//   ARK pin 照合 + snpguest によるチェーン/署名検証 → 検証通過後に CHIP_ID を抽出。
//
// ベンダー検証 (チェーン + Report 署名) は snpguest に委譲する。詳細は
// snp_provision.hpp の方針コメントを参照。
//
#include "snp_provision.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

#include <sys/wait.h>
#include <unistd.h>

#include "error.hpp"
#include "io.hpp"
#include "pki_util.hpp"

#include "amd_ark_pubkeys.hpp"

namespace tee_anchor::snp {

namespace {

constexpr uint32_t kSigAlgoEcdsaP384Sha384 = 1;  // ABI spec Table 139

uint32_t rd_u32le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

std::string join_path(const std::string& dir, const char* name) {
    if (dir.empty()) return name;
    return dir.back() == '/' ? dir + name : dir + "/" + name;
}

// 引数を直接 execv に渡す (シェルを介さないので injection の心配が無い)。
// 戻り値は子プロセスの exit code。exec 失敗時は -1。
int run_process(const std::vector<std::string>& argv) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        std::vector<char*> c;
        c.reserve(argv.size() + 1);
        for (const auto& a : argv) c.push_back(const_cast<char*>(a.c_str()));
        c.push_back(nullptr);
        execvp(c[0], c.data());
        // exec 失敗時のみ到達
        std::perror(("execvp(" + argv[0] + ")").c_str());
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

}  // namespace

void validate_report_header(const std::vector<uint8_t>& report) {
    if (report.size() != kReportLen) {
        throw TeeAnchorError(
            "attestation report has unexpected length " +
            std::to_string(report.size()) + " (expected " +
            std::to_string(kReportLen) + " bytes)");
    }
    const uint32_t version  = rd_u32le(&report[kOffVersion]);
    const uint32_t sig_algo = rd_u32le(&report[kOffSigAlgo]);

    // 既知バージョンのみ受理する。CHIP_ID(0x1A0)/SIGNATURE(0x2A0) のオフセットは
    // v2〜v5 で不変 (追加はすべて旧 Reserved 領域)。未知の上位バージョンは、
    // レイアウトが変わっている可能性があるため安全側に倒して拒否する。
    if (version < 2 || version > 5) {
        throw TeeAnchorError(
            "unsupported attestation report VERSION " + std::to_string(version) +
            " (this build supports 2..5; CHIP_ID offset assumed stable in that range)");
    }
    if (sig_algo != kSigAlgoEcdsaP384Sha384) {
        throw TeeAnchorError(
            "unsupported SIGNATURE_ALGO " + std::to_string(sig_algo) +
            " (expected 1 = ECDSA P-384 with SHA-384)");
    }
}

std::vector<uint8_t> extract_chip_id_from_report(const std::vector<uint8_t>& report) {
    if (report.size() < kOffChipId + kChipIdLen) {
        throw TeeAnchorError("attestation report too short for CHIP_ID");
    }
    std::vector<uint8_t> chip_id(report.begin() + kOffChipId,
                                 report.begin() + kOffChipId + kChipIdLen);

    const bool all_zero = std::all_of(chip_id.begin(), chip_id.end(),
                                      [](uint8_t b) { return b == 0; });
    if (all_zero) {
        // MaskChipId=1 のとき CHIP_ID は 0 埋めされる (ABI spec Table 23)。
        // この場合 chip に固有でない値を bind してしまい binding が無意味になるため、
        // SGX の暗号化 PPID (警告のみ) とは異なり、SNP では明確にエラーとする。
        throw TeeAnchorError(
            "CHIP_ID is all zero: the platform has MaskChipId set, so the report "
            "carries no chip-unique identifier to bind. Provisioning aborted.");
    }
    return chip_id;
}

const char* verify_ark_pin(const std::string& certs_dir) {
    const std::string ark_path = join_path(certs_dir, "ark.pem");
    if (!path_exists(ark_path)) {
        throw TeeAnchorError("ARK certificate not found: " + ark_path +
                             " (expected ark.pem in the certs directory)");
    }
    X509Ptr ark = pki::load_pem_cert(ark_path);
    const std::vector<uint8_t> digest = pki::pubkey_spki_sha384(ark.get());
    const char* generation = match_ark_pin(digest);
    if (!generation) {
        throw TeeAnchorError(
            "ARK public key does not match any pinned AMD root "
            "(Milan/Genoa/Turin). The certs directory may carry an unknown or "
            "untrusted root.");
    }
    return generation;
}

void run_snpguest_verify(const std::string& snpguest_bin,
                         const std::string& certs_dir,
                         const std::string& report_path) {
    const std::string bin = snpguest_bin.empty() ? "snpguest" : snpguest_bin;

    const int rc_certs = run_process({bin, "verify", "certs", certs_dir});
    if (rc_certs == 127) {
        throw TeeAnchorError(
            "failed to execute snpguest (\"" + bin + "\"). Install it "
            "(see provision/sev-snp/snp-sample) or pass --snpguest <path>.");
    }
    if (rc_certs != 0) {
        throw TeeAnchorError(
            "snpguest verify certs failed (exit " + std::to_string(rc_certs) +
            "): the VCEK certificate chain (ARK->ASK->VCEK) did not validate.");
    }

    const int rc_att = run_process({bin, "verify", "attestation", certs_dir, report_path});
    if (rc_att != 0) {
        throw TeeAnchorError(
            "snpguest verify attestation failed (exit " + std::to_string(rc_att) +
            "): the report signature did not verify against the VCEK.");
    }
}

SnpVerifyResult
verify_and_extract(const std::string& report_path,
                   const std::string& certs_dir,
                   const std::string& snpguest_bin) {
    // 1. Report のロード + ヘッダ検証
    auto report = read_file(report_path);
    validate_report_header(report);
    const uint32_t version = rd_u32le(&report[kOffVersion]);

    // 2. ARK pin 照合 (信頼根はコード側で握る)
    const char* generation = verify_ark_pin(certs_dir);

    // 3. snpguest によるチェーン検証 + Report 署名検証 (ベンダー検証の委譲)
    run_snpguest_verify(snpguest_bin, certs_dir, report_path);

    // 4. 検証通過後に CHIP_ID を抽出 + VCEK leaf をロード
    std::vector<uint8_t> chip_id = extract_chip_id_from_report(report);

    const std::string vcek_path = join_path(certs_dir, "vcek.pem");
    if (!path_exists(vcek_path)) {
        throw TeeAnchorError("VCEK certificate not found: " + vcek_path);
    }
    X509Ptr vcek = pki::load_pem_cert(vcek_path);

    // (任意のダメ押し) VCEK の hwID 拡張と Report の CHIP_ID が一致するか確認する。
    // snpguest が Report 署名 (CHIP_ID を含む) と VCEK チェーンを検証済みなので
    // 通常は一致するが、両ソースの突き合わせを明示しておく。
    {
        Asn1ObjectPtr oid = pki::make_oid(OID_AMD_SEV_HWID);
        const int idx = X509_get_ext_by_OBJ(vcek.get(), oid.get(), -1);
        if (idx >= 0) {
            X509_EXTENSION* ext = X509_get_ext(vcek.get(), idx);
            const ASN1_OCTET_STRING* data = ext ? X509_EXTENSION_get_data(ext) : nullptr;
            if (data) {
                const uint8_t* p = ASN1_STRING_get0_data(data);
                const int n = ASN1_STRING_length(data);
                if (n == static_cast<int>(chip_id.size()) &&
                    !std::equal(chip_id.begin(), chip_id.end(), p)) {
                    throw TeeAnchorError(
                        "CHIP_ID in attestation report does not match the VCEK hwID "
                        "extension; report and certificate disagree on the chip.");
                }
            }
        }
    }

    return SnpVerifyResult{std::move(chip_id), version, generation, std::move(vcek)};
}

}  // namespace tee_anchor::snp

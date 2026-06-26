//
// snp_provision.cpp
//
// Phase 2 / SEV-SNP:
//   Attestation Report + VCEK 証明書チェーンを入力に取り、
//   ARK pin 照合 + 自前 (OpenSSL) のチェーン/署名検証 → 検証通過後に CHIP_ID を抽出。
//
// ベンダー検証 (ARK→ASK→VCEK チェーン + VCEK による Report 署名) は、SGX の
// PCK チェーン検証 (verify_pck_chain) / CCA の ES384 検証 (verify_es384) と同じく
// OpenSSL で自前実装する。snpguest への subprocess 依存は廃止した。
//
#include "snp_provision.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>

#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "error.hpp"
#include "io.hpp"
#include "pki_util.hpp"

#include "amd_ark_pubkeys.hpp"

namespace tee_anchor::snp {

namespace {

constexpr uint32_t kSigAlgoEcdsaP384Sha384 = 1;  // ABI spec Table 139

using EcdsaSigPtr = std::unique_ptr<ECDSA_SIG, Deleter<ECDSA_SIG_free>>;
using MdCtxPtr    = std::unique_ptr<EVP_MD_CTX, Deleter<EVP_MD_CTX_free>>;

uint32_t rd_u32le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

std::string join_path(const std::string& dir, const char* name) {
    if (dir.empty()) return name;
    return dir.back() == '/' ? dir + name : dir + "/" + name;
}

// 72 バイトのリトルエンディアン整数 (SIGNATURE の R/S フィールド) を BIGNUM に変換する。
// BN_bin2bn はビッグエンディアンを取るので、バイト列を反転してから渡す。
BnPtr le_bytes_to_bn(const uint8_t* le, size_t len) {
    std::vector<uint8_t> be(len);
    for (size_t i = 0; i < len; ++i) be[i] = le[len - 1 - i];
    BnPtr bn(BN_bin2bn(be.data(), static_cast<int>(len), nullptr));
    if (!bn) throw_openssl_error("BN_bin2bn (SNP signature component)");
    return bn;
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

SnpChain verify_vcek_chain(const std::string& certs_dir) {
    // 1. ARK / ASK / VCEK を PEM からロード
    const std::string ark_path  = join_path(certs_dir, "ark.pem");
    const std::string ask_path  = join_path(certs_dir, "ask.pem");
    const std::string vcek_path = join_path(certs_dir, "vcek.pem");
    if (!path_exists(ark_path)) {
        throw TeeAnchorError("ARK certificate not found: " + ark_path +
                             " (expected ark.pem in the certs directory)");
    }
    if (!path_exists(ask_path)) {
        throw TeeAnchorError("ASK certificate not found: " + ask_path +
                             " (expected ask.pem in the certs directory)");
    }
    if (!path_exists(vcek_path)) {
        throw TeeAnchorError("VCEK certificate not found: " + vcek_path +
                             " (expected vcek.pem in the certs directory)");
    }
    X509Ptr ark  = pki::load_pem_cert(ark_path);
    X509Ptr ask  = pki::load_pem_cert(ask_path);
    X509Ptr vcek = pki::load_pem_cert(vcek_path);

    // 2. ARK pin 照合 (信頼根はコード側で握る)。SGX の Intel root ハードコードと
    //    同じプロパティ。ARK は RSA-4096 で生鍵が嵩むため SPKI の SHA-384 を pin。
    const std::vector<uint8_t> digest = pki::pubkey_spki_sha384(ark.get());
    const char* generation = match_ark_pin(digest);
    if (!generation) {
        throw TeeAnchorError(
            "ARK public key does not match any pinned AMD root "
            "(Milan/Genoa/Turin). The certs directory may carry an unknown or "
            "untrusted root.");
    }

    // 3. pin した ARK を信頼アンカーに、ASK を untrusted 中間として VCEK を検証する。
    //    (SGX の verify_pck_chain と同じ X509_STORE フロー。)
    X509StorePtr store(X509_STORE_new());
    if (!store) throw_openssl_error("X509_STORE_new");
    if (X509_STORE_add_cert(store.get(), ark.get()) != 1) {
        throw_openssl_error("X509_STORE_add_cert (ARK)");
    }

    SkX509Ptr untrusted(sk_X509_new_null());
    if (!untrusted) throw_openssl_error("sk_X509_new_null");
    if (sk_X509_push(untrusted.get(), ask.get()) == 0) {
        throw_openssl_error("sk_X509_push (ASK)");
    }

    X509StoreCtxPtr ctx(X509_STORE_CTX_new());
    if (!ctx) throw_openssl_error("X509_STORE_CTX_new");
    if (X509_STORE_CTX_init(ctx.get(), store.get(), vcek.get(), untrusted.get()) != 1) {
        throw_openssl_error("X509_STORE_CTX_init");
    }
    // CRL チェックはここでは行わない (失効は別経路で扱う)。

    if (X509_verify_cert(ctx.get()) != 1) {
        const int err = X509_STORE_CTX_get_error(ctx.get());
        throw TeeAnchorError(
            std::string("VCEK certificate chain verification failed "
                        "(ARK->ASK->VCEK): ") +
            X509_verify_cert_error_string(err));
    }

    return SnpChain{std::move(vcek), generation};
}

void verify_report_signature(const std::vector<uint8_t>& report, X509* vcek) {
    if (report.size() < kOffSignature + 2 * kEcdsaCompLen) {
        throw TeeAnchorError("attestation report too short for SIGNATURE field");
    }

    // VCEK 公開鍵が EC (P-384) であることを確認する。AMD VCEK は ECDSA P-384/SHA-384。
    EVP_PKEY* pk = X509_get0_pubkey(vcek);  // borrowed
    if (!pk) throw_openssl_error("X509_get0_pubkey (VCEK)");
    if (EVP_PKEY_base_id(pk) != EVP_PKEY_EC) {
        throw TeeAnchorError("VCEK public key is not EC (expected ECDSA P-384)");
    }

    // SIGNATURE フィールドの R||S (各 72B LE) を ECDSA_SIG に組み立てる。
    BnPtr r = le_bytes_to_bn(&report[kOffSignature], kEcdsaCompLen);
    BnPtr s = le_bytes_to_bn(&report[kOffSignature + kEcdsaCompLen], kEcdsaCompLen);

    EcdsaSigPtr sig(ECDSA_SIG_new());
    if (!sig) throw_openssl_error("ECDSA_SIG_new");
    if (ECDSA_SIG_set0(sig.get(), r.get(), s.get()) != 1) {
        throw_openssl_error("ECDSA_SIG_set0");
    }
    r.release();  // 所有権は ECDSA_SIG に移った
    s.release();

    const int der_len = i2d_ECDSA_SIG(sig.get(), nullptr);
    if (der_len <= 0) throw_openssl_error("i2d_ECDSA_SIG (length)");
    std::vector<uint8_t> der(static_cast<size_t>(der_len));
    unsigned char* pp = der.data();
    if (i2d_ECDSA_SIG(sig.get(), &pp) != der_len) throw_openssl_error("i2d_ECDSA_SIG");

    // 署名対象は Report 先頭 [0, 0x2A0)。SHA-384 でハッシュして検証する。
    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) throw_openssl_error("EVP_MD_CTX_new");
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha384(), nullptr, pk) != 1) {
        throw_openssl_error("EVP_DigestVerifyInit (ECDSA P-384/SHA-384)");
    }
    const int rc = EVP_DigestVerify(ctx.get(), der.data(), der.size(),
                                    report.data(), kOffSignedEnd);
    if (rc < 0) throw_openssl_error("EVP_DigestVerify (SNP report)");
    if (rc != 1) {
        throw TeeAnchorError(
            "attestation report signature did not verify against the VCEK "
            "public key (report may be forged or the VCEK does not match)");
    }
}

SnpVerifyResult
verify_and_extract(const std::string& report_path,
                   const std::string& certs_dir) {
    // 1. Report のロード + ヘッダ検証
    auto report = read_file(report_path);
    validate_report_header(report);
    const uint32_t version = rd_u32le(&report[kOffVersion]);

    // 2. ARK pin 照合 + ARK→ASK→VCEK チェーン検証 (信頼根はコード側で握る)
    SnpChain chain = verify_vcek_chain(certs_dir);

    // 3. VCEK による Report 署名検証 (ECDSA P-384/SHA-384)
    verify_report_signature(report, chain.vcek.get());

    // 4. 検証通過後に CHIP_ID を抽出
    std::vector<uint8_t> chip_id = extract_chip_id_from_report(report);

    // (ダメ押し) VCEK の hwID 拡張と Report の CHIP_ID が一致するか確認する。
    // Report 署名 (CHIP_ID を含む) と VCEK チェーンを既に検証済みなので通常は
    // 一致するが、両ソースの突き合わせを明示しておく。
    {
        Asn1ObjectPtr oid = pki::make_oid(OID_AMD_SEV_HWID);
        const int idx = X509_get_ext_by_OBJ(chain.vcek.get(), oid.get(), -1);
        if (idx >= 0) {
            X509_EXTENSION* ext = X509_get_ext(chain.vcek.get(), idx);
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

    return SnpVerifyResult{std::move(chip_id), version, chain.generation,
                           std::move(chain.vcek)};
}

}  // namespace tee_anchor::snp

//
// crl_issue.cpp — `tee-anchor crl-issue` の実装。
//
#include "crl_issue.hpp"

#include <array>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <string_view>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "error.hpp"
#include "io.hpp"
#include "openssl_raii.hpp"
#include "pki_util.hpp"

#include "revocation_db.hpp"

namespace tee_anchor::ca {

namespace {

constexpr std::array<std::pair<std::string_view, int>, 9> kReasonMap = {{
    {"unspecified",          0},
    {"keyCompromise",        1},
    {"cACompromise",         2},
    {"affiliationChanged",   3},
    {"superseded",           4},
    {"cessationOfOperation", 5},
    {"certificateHold",      6},
    {"privilegeWithdrawn",   9},
    {"aACompromise",         10},
}};

int reason_to_int(const std::string& name) {
    for (auto& [n, v] : kReasonMap) if (n == name) return v;
    throw TeeAnchorError("unknown reason name in DB: '" + name + "'");
}

Asn1IntPtr asn1_int_from_hex(const std::string& hex) {
    BIGNUM* bn = nullptr;
    if (BN_hex2bn(&bn, hex.c_str()) == 0 || bn == nullptr) {
        if (bn) BN_free(bn);
        throw_openssl_error("BN_hex2bn (serial=" + hex + ")");
    }
    BnPtr bn_owned(bn);
    Asn1IntPtr ai(BN_to_ASN1_INTEGER(bn_owned.get(), nullptr));
    if (!ai) throw_openssl_error("BN_to_ASN1_INTEGER");
    return ai;
}

// "YYYYMMDDHHMMSSZ" 文字列を ASN1_TIME (GeneralizedTime) として生成。
std::unique_ptr<ASN1_TIME, Deleter<ASN1_TIME_free>>
asn1_gentime_from_string(const std::string& ts) {
    std::unique_ptr<ASN1_TIME, Deleter<ASN1_TIME_free>> t(
        ASN1_GENERALIZEDTIME_new());
    if (!t) throw_openssl_error("ASN1_GENERALIZEDTIME_new");
    if (ASN1_GENERALIZEDTIME_set_string(t.get(), ts.c_str()) == 0) {
        throw TeeAnchorError("invalid GeneralizedTime in DB: '" + ts + "'");
    }
    return t;
}

void add_crl_reason_extension(X509_REVOKED* rev, const std::string& reason_name) {
    if (reason_name.empty()) return;
    const int code = reason_to_int(reason_name);
    std::unique_ptr<ASN1_ENUMERATED, Deleter<ASN1_ENUMERATED_free>> e(
        ASN1_ENUMERATED_new());
    if (!e) throw_openssl_error("ASN1_ENUMERATED_new");
    if (ASN1_ENUMERATED_set(e.get(), code) != 1) {
        throw_openssl_error("ASN1_ENUMERATED_set");
    }
    if (X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason, e.get(),
                                  /*crit=*/0, /*flags=*/0) != 1) {
        throw_openssl_error("X509_REVOKED_add1_ext_i2d (crl_reason)");
    }
}

}  // namespace

void run_crl_issue(const CrlIssueArgs& args) {
    if (args.ca_key_path.empty())  throw TeeAnchorError("--ca-key is required");
    if (args.ca_cert_path.empty()) throw TeeAnchorError("--ca-cert is required");
    if (args.out_path.empty())     throw TeeAnchorError("--out is required");
    if (args.validity_days <= 0)   throw TeeAnchorError("--validity-days must be positive");

    // 1. CA をロード + 鍵と cert の整合性
    EvpPkeyPtr ca_key  = pki::load_pem_private_key(args.ca_key_path);
    X509Ptr    ca_cert = pki::load_pem_cert(args.ca_cert_path);
    if (X509_check_private_key(ca_cert.get(), ca_key.get()) != 1) {
        throw TeeAnchorError("CA private key does not match CA certificate");
    }

    // 2. DB をロードして crl_number をインクリメント
    const std::string db_path = args.db_path.empty()
        ? default_db_path(args.ca_cert_path) : args.db_path;
    RevocationDb db = load_revocation_db(db_path);
    db.crl_number += 1;

    // 3. CRL 骨格
    X509CrlPtr crl(X509_CRL_new());
    if (!crl) throw_openssl_error("X509_CRL_new");

    if (X509_CRL_set_version(crl.get(), 1) != 1) {  // v2 = value 1
        throw_openssl_error("X509_CRL_set_version");
    }
    if (X509_CRL_set_issuer_name(crl.get(),
            X509_get_subject_name(ca_cert.get())) != 1) {
        throw_openssl_error("X509_CRL_set_issuer_name");
    }

    // thisUpdate / nextUpdate
    {
        std::unique_ptr<ASN1_TIME, Deleter<ASN1_TIME_free>> tnow(ASN1_TIME_new());
        if (!tnow) throw_openssl_error("ASN1_TIME_new (this)");
        if (X509_gmtime_adj(tnow.get(), 0) == nullptr) {
            throw_openssl_error("X509_gmtime_adj (this)");
        }
        if (X509_CRL_set1_lastUpdate(crl.get(), tnow.get()) != 1) {
            throw_openssl_error("X509_CRL_set1_lastUpdate");
        }
    }
    {
        std::unique_ptr<ASN1_TIME, Deleter<ASN1_TIME_free>> tnxt(ASN1_TIME_new());
        if (!tnxt) throw_openssl_error("ASN1_TIME_new (next)");
        if (X509_gmtime_adj(tnxt.get(),
                static_cast<long>(args.validity_days) * 86400L) == nullptr) {
            throw_openssl_error("X509_gmtime_adj (next)");
        }
        if (X509_CRL_set1_nextUpdate(crl.get(), tnxt.get()) != 1) {
            throw_openssl_error("X509_CRL_set1_nextUpdate");
        }
    }

    // 4. 各エントリを X509_REVOKED として追加
    for (const auto& e : db.entries) {
        X509_REVOKED* rev_raw = X509_REVOKED_new();
        if (!rev_raw) throw_openssl_error("X509_REVOKED_new");
        // X509_CRL_add0_revoked が成功すれば所有権が CRL 側に移る。
        // 失敗時に rev を解放するため try でくくる。
        try {
            Asn1IntPtr sn = asn1_int_from_hex(e.serial_hex);
            if (X509_REVOKED_set_serialNumber(rev_raw, sn.get()) != 1) {
                throw_openssl_error("X509_REVOKED_set_serialNumber");
            }
            auto rd = asn1_gentime_from_string(e.revocation_date);
            if (X509_REVOKED_set_revocationDate(rev_raw, rd.get()) != 1) {
                throw_openssl_error("X509_REVOKED_set_revocationDate");
            }
            add_crl_reason_extension(rev_raw, e.reason);
        } catch (...) {
            X509_REVOKED_free(rev_raw);
            throw;
        }
        if (X509_CRL_add0_revoked(crl.get(), rev_raw) != 1) {
            X509_REVOKED_free(rev_raw);
            throw_openssl_error("X509_CRL_add0_revoked");
        }
    }

    // 5. CRL 拡張: CRL Number と AKI
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, /*issuer=*/ca_cert.get(), /*subject=*/nullptr,
                   /*req=*/nullptr, /*crl=*/crl.get(), 0);

    {
        // CRL Number 拡張は INTEGER であり X509V3_EXT_conf_nid (文字列設定型) では
        // 扱えないため、i2d 経由で直接追加する。
        Asn1IntPtr crl_num(ASN1_INTEGER_new());
        if (!crl_num) throw_openssl_error("ASN1_INTEGER_new (crl_number)");
        if (ASN1_INTEGER_set(crl_num.get(),
                             static_cast<long>(db.crl_number)) != 1) {
            throw_openssl_error("ASN1_INTEGER_set (crl_number)");
        }
        if (X509_CRL_add1_ext_i2d(crl.get(), NID_crl_number, crl_num.get(),
                                  /*crit=*/0, /*flags=*/0) != 1) {
            throw_openssl_error("X509_CRL_add1_ext_i2d (crl_number)");
        }
    }
    {
        X509ExtPtr ext(X509V3_EXT_conf_nid(nullptr, &ctx,
            NID_authority_key_identifier,
            const_cast<char*>("keyid:always")));
        if (!ext) throw_openssl_error("X509V3_EXT_conf_nid (AKI)");
        if (X509_CRL_add_ext(crl.get(), ext.get(), -1) != 1) {
            throw_openssl_error("X509_CRL_add_ext (AKI)");
        }
    }

    // 6. ソート + 署名
    if (X509_CRL_sort(crl.get()) != 1) throw_openssl_error("X509_CRL_sort");
    if (X509_CRL_sign(crl.get(), ca_key.get(),
                      pki::digest_for_signing_key(ca_key.get())) == 0) {
        throw_openssl_error("X509_CRL_sign");
    }

    // 7. PEM 出力
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio) throw_openssl_error("BIO_new (mem)");
    if (PEM_write_bio_X509_CRL(bio.get(), crl.get()) != 1) {
        throw_openssl_error("PEM_write_bio_X509_CRL");
    }
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem);
    write_file(args.out_path, mem->data, mem->length, 0644);

    // 8. DB を保存 (新 crl_number)
    save_revocation_db(db_path, db);

    std::printf("CRL issued:\n");
    std::printf("  crl-number    : %llu\n", static_cast<unsigned long long>(db.crl_number));
    std::printf("  revoked count : %zu\n",   db.entries.size());
    std::printf("  validity      : %d days\n", args.validity_days);
    std::printf("  output        : %s\n",    args.out_path.c_str());
    std::printf("  db            : %s\n",    db_path.c_str());
}

int cli_crl_issue(int argc, char** argv) {
    CrlIssueArgs args;
    auto need_value = [&](int& i, const char* opt) -> const char* {
        if (i + 1 >= argc) {
            throw TeeAnchorError(std::string(opt) + " requires a value");
        }
        return argv[++i];
    };

    try {
        for (int i = 0; i < argc; ++i) {
            std::string a = argv[i];
            if      (a == "--ca-key")        args.ca_key_path   = need_value(i, "--ca-key");
            else if (a == "--ca-cert")       args.ca_cert_path  = need_value(i, "--ca-cert");
            else if (a == "--out")           args.out_path      = need_value(i, "--out");
            else if (a == "--validity-days") args.validity_days = std::stoi(need_value(i, "--validity-days"));
            else if (a == "--db")            args.db_path       = need_value(i, "--db");
            else if (a == "-h" || a == "--help") {
                std::printf(
                    "Usage: tee-anchor crl-issue --ca-key <file> --ca-cert <file> --out <file> [options]\n"
                    "\n"
                    "Options:\n"
                    "  --ca-key <file>        (required) organization CA private key (PEM)\n"
                    "  --ca-cert <file>       (required) organization CA certificate (PEM)\n"
                    "  --out <file>           (required) output CRL (PEM)\n"
                    "  --validity-days <N>    CRL nextUpdate distance in days (default: 7)\n"
                    "  --db <path>            revocation DB path (default: <dir of ca-cert>/revocations.txt)\n");
                return 0;
            }
            else {
                throw TeeAnchorError("unknown argument: " + a);
            }
        }
        run_crl_issue(args);
        return 0;
    } catch (const TeeAnchorError& e) {
        std::fprintf(stderr, "[error] crl-issue: %s\n", e.what());
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[error] crl-issue: %s\n", e.what());
        return 2;
    }
}

}  // namespace tee_anchor::ca

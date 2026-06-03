//
// revoke.cpp — `tee-anchor revoke` の実装。
//
#include "revoke.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <ctime>
#include <stdexcept>
#include <string>
#include <string_view>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/x509.h>

#include "error.hpp"
#include "openssl_raii.hpp"
#include "pki_util.hpp"

#include "revocation_db.hpp"

namespace tee_anchor::ca {

namespace {

// RFC 5280 CRLReason 名 (OpenSSL X509V3_EXT_conf_nid(NID_crl_reason, ...) 互換)
constexpr std::array<std::string_view, 9> kReasonNames = {
    "unspecified",
    "keyCompromise",
    "cACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
    "privilegeWithdrawn",
    "aACompromise",
};

bool is_valid_reason(const std::string& r) {
    if (r.empty()) return true;  // reason 拡張無し
    for (auto& n : kReasonNames) if (n == r) return true;
    return false;
}

std::string generalized_time_now_utc() {
    const std::time_t now = std::time(nullptr);
    std::tm tm_utc{};
    gmtime_r(&now, &tm_utc);
    char ts[16];
    std::strftime(ts, sizeof(ts), "%Y%m%d%H%M%SZ", &tm_utc);
    return std::string(ts);
}

std::string serial_hex_lower(X509* cert) {
    const ASN1_INTEGER* sn = X509_get0_serialNumber(cert);
    if (!sn) throw_openssl_error("X509_get0_serialNumber");
    BnPtr bn(ASN1_INTEGER_to_BN(sn, nullptr));
    if (!bn) throw_openssl_error("ASN1_INTEGER_to_BN");
    char* hex = BN_bn2hex(bn.get());
    if (!hex) throw_openssl_error("BN_bn2hex");
    std::string s(hex);
    OPENSSL_free(hex);
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

}  // namespace

void run_revoke(const RevokeArgs& args) {
    if (args.ca_cert_path.empty()) throw TeeAnchorError("--ca-cert is required");
    if (args.cert_path.empty())    throw TeeAnchorError("--cert is required");
    if (!is_valid_reason(args.reason)) {
        std::string allowed;
        for (auto& n : kReasonNames) { if (!allowed.empty()) allowed += ", "; allowed += n; }
        throw TeeAnchorError("invalid --reason: '" + args.reason +
                             "' (allowed: " + allowed + ")");
    }

    // 1. CA cert と 失効対象 endorsement cert を読む
    X509Ptr ca_cert      = pki::load_pem_cert(args.ca_cert_path);
    X509Ptr endorsement  = pki::load_pem_cert(args.cert_path);

    // 2. 発行者整合性チェック
    if (X509_NAME_cmp(X509_get_subject_name(ca_cert.get()),
                      X509_get_issuer_name(endorsement.get())) != 0) {
        throw TeeAnchorError(
            "subject(--ca-cert) != issuer(--cert): " + args.cert_path +
            " was not issued by " + args.ca_cert_path);
    }

    // 3. serial 抽出
    const std::string serial_hex = serial_hex_lower(endorsement.get());

    // 4. DB 読み込み (無ければ空)
    const std::string db_path = args.db_path.empty()
        ? default_db_path(args.ca_cert_path) : args.db_path;
    RevocationDb db = load_revocation_db(db_path);

    // 5. 既出の serial なら更新せず警告のみ
    for (auto& e : db.entries) {
        if (e.serial_hex == serial_hex) {
            std::printf("[warn] serial %s already in DB (revoked at %s); not modified.\n",
                        serial_hex.c_str(), e.revocation_date.c_str());
            return;
        }
    }

    // 6. 追加
    RevocationEntry e;
    e.serial_hex      = serial_hex;
    e.revocation_date = generalized_time_now_utc();
    e.reason          = args.reason;
    db.entries.push_back(e);

    save_revocation_db(db_path, db);

    std::printf("revoked:\n");
    std::printf("  serial          : %s\n", e.serial_hex.c_str());
    std::printf("  revocation_date : %s\n", e.revocation_date.c_str());
    std::printf("  reason          : %s\n", e.reason.empty() ? "(none)" : e.reason.c_str());
    std::printf("  db              : %s (%zu entries, crl-number=%llu)\n",
                db_path.c_str(), db.entries.size(),
                static_cast<unsigned long long>(db.crl_number));
    std::printf("Run `tee-anchor crl-issue` to publish a new CRL reflecting this change.\n");
}

int cli_revoke(int argc, char** argv) {
    RevokeArgs args;
    auto need_value = [&](int& i, const char* opt) -> const char* {
        if (i + 1 >= argc) {
            throw TeeAnchorError(std::string(opt) + " requires a value");
        }
        return argv[++i];
    };

    try {
        for (int i = 0; i < argc; ++i) {
            std::string a = argv[i];
            if      (a == "--ca-cert") args.ca_cert_path = need_value(i, "--ca-cert");
            else if (a == "--cert")    args.cert_path    = need_value(i, "--cert");
            else if (a == "--reason")  args.reason       = need_value(i, "--reason");
            else if (a == "--db")      args.db_path      = need_value(i, "--db");
            else if (a == "-h" || a == "--help") {
                std::printf(
                    "Usage: tee-anchor revoke --ca-cert <file> --cert <file> [options]\n"
                    "\n"
                    "Options:\n"
                    "  --ca-cert <file>    (required) organization CA certificate (PEM)\n"
                    "  --cert <file>       (required) endorsement certificate to revoke (PEM)\n"
                    "  --reason <name>     CRL reason: unspecified|keyCompromise|cACompromise|\n"
                    "                                   affiliationChanged|superseded|\n"
                    "                                   cessationOfOperation|certificateHold|\n"
                    "                                   privilegeWithdrawn|aACompromise\n"
                    "  --db <path>         revocation DB path (default: <dir of ca-cert>/revocations.txt)\n");
                return 0;
            }
            else {
                throw TeeAnchorError("unknown argument: " + a);
            }
        }
        run_revoke(args);
        return 0;
    } catch (const TeeAnchorError& e) {
        std::fprintf(stderr, "[error] revoke: %s\n", e.what());
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[error] revoke: %s\n", e.what());
        return 2;
    }
}

}  // namespace tee_anchor::ca

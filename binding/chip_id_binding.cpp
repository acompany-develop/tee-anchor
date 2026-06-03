//
// chip_id_binding.cpp — ChipIdBinding 拡張の DER エンコード / デコード実装。
//
#include "chip_id_binding.hpp"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>

#include <openssl/asn1.h>
#include <openssl/objects.h>

#include "error.hpp"
#include "pki_util.hpp"

namespace tee_anchor::binding {

namespace {

// ---- DER 構築用の小道具 ----------------------------------------------------
std::vector<uint8_t> der_length(size_t len) {
    std::vector<uint8_t> out;
    if (len < 0x80) {
        out.push_back(static_cast<uint8_t>(len));
    } else if (len < 0x100) {
        out.push_back(0x81);
        out.push_back(static_cast<uint8_t>(len));
    } else if (len < 0x10000) {
        out.push_back(0x82);
        out.push_back(static_cast<uint8_t>(len >> 8));
        out.push_back(static_cast<uint8_t>(len & 0xff));
    } else {
        throw TeeAnchorError("DER length unexpectedly large");
    }
    return out;
}

std::vector<uint8_t> der_tlv(uint8_t tag, const std::vector<uint8_t>& value) {
    std::vector<uint8_t> out;
    out.reserve(1 + 4 + value.size());
    out.push_back(tag);
    auto l = der_length(value.size());
    out.insert(out.end(), l.begin(), l.end());
    out.insert(out.end(), value.begin(), value.end());
    return out;
}

std::string generalized_time_now_utc() {
    const std::time_t now = std::time(nullptr);
    std::tm tm_utc{};
    gmtime_r(&now, &tm_utc);
    char ts[16];
    std::strftime(ts, sizeof(ts), "%Y%m%d%H%M%SZ", &tm_utc);
    return std::string(ts);
}

}  // namespace

std::vector<uint8_t>
encode_chip_id_binding(uint8_t tee_type,
                       const std::vector<uint8_t>& chip_id) {
    std::vector<uint8_t> seq;

    // ENUMERATED teeType
    auto enum_tlv = der_tlv(0x0A, std::vector<uint8_t>{tee_type});
    seq.insert(seq.end(), enum_tlv.begin(), enum_tlv.end());

    // OCTET STRING chipId
    auto octet_tlv = der_tlv(0x04, chip_id);
    seq.insert(seq.end(), octet_tlv.begin(), octet_tlv.end());

    // GeneralizedTime issuedAt (15 文字, UTC)
    const std::string ts = generalized_time_now_utc();
    std::vector<uint8_t> ts_bytes(ts.begin(), ts.end());
    auto time_tlv = der_tlv(0x18, ts_bytes);
    seq.insert(seq.end(), time_tlv.begin(), time_tlv.end());

    return der_tlv(0x30, seq);  // outer SEQUENCE
}

X509ExtPtr make_chip_id_binding_extension(const std::vector<uint8_t>& binding_der) {
    Asn1ObjectPtr oid = pki::make_oid(kOidChipIdBinding);

    Asn1OctStrPtr value(ASN1_OCTET_STRING_new());
    if (!value) throw_openssl_error("ASN1_OCTET_STRING_new");
    if (ASN1_OCTET_STRING_set(value.get(), binding_der.data(),
                              static_cast<int>(binding_der.size())) != 1) {
        throw_openssl_error("ASN1_OCTET_STRING_set");
    }

    X509_EXTENSION* raw = X509_EXTENSION_create_by_OBJ(
        nullptr, oid.get(), /*crit=*/1, value.get());
    if (!raw) throw_openssl_error("X509_EXTENSION_create_by_OBJ");
    return X509ExtPtr(raw);
}

ChipIdBinding decode_chip_id_binding(const uint8_t* der, size_t der_len) {
    const unsigned char* p = der;
    long len = 0;
    int tag = 0, xclass = 0;

    // 外側 SEQUENCE
    int r = ASN1_get_object(&p, &len, &tag, &xclass, static_cast<long>(der_len));
    if ((r & 0x80) || tag != V_ASN1_SEQUENCE) {
        throw TeeAnchorError("ChipIdBinding: outer SEQUENCE expected");
    }
    const unsigned char* end = p + len;

    auto must_read = [&](int expect_tag, const char* what) -> std::pair<const unsigned char*, long> {
        long L = 0; int T = 0, C = 0;
        int rr = ASN1_get_object(&p, &L, &T, &C, end - p);
        if ((rr & 0x80) || T != expect_tag) {
            throw TeeAnchorError(std::string("ChipIdBinding: ") + what + " expected");
        }
        const unsigned char* val = p;
        p += L;
        return {val, L};
    };

    // ENUMERATED teeType
    auto [tt_p, tt_len] = must_read(V_ASN1_ENUMERATED, "ENUMERATED teeType");
    if (tt_len != 1) {
        throw TeeAnchorError("ChipIdBinding: teeType length must be 1, got " +
                             std::to_string(tt_len));
    }
    const uint8_t tee_type = tt_p[0];

    // OCTET STRING chipId
    auto [ci_p, ci_len] = must_read(V_ASN1_OCTET_STRING, "OCTET STRING chipId");
    std::vector<uint8_t> chip_id(ci_p, ci_p + ci_len);

    // GeneralizedTime issuedAt
    auto [it_p, it_len] = must_read(V_ASN1_GENERALIZEDTIME, "GeneralizedTime issuedAt");
    std::string issued_at(reinterpret_cast<const char*>(it_p), it_len);

    // Optional notes は Phase 1 では未使用。残りは無視する。

    return ChipIdBinding{tee_type, std::move(chip_id), std::move(issued_at)};
}

ChipIdBinding extract_chip_id_binding(X509* cert) {
    Asn1ObjectPtr oid = pki::make_oid(kOidChipIdBinding);
    const int idx = X509_get_ext_by_OBJ(cert, oid.get(), -1);
    if (idx < 0) {
        throw TeeAnchorError("ChipIdBinding extension (" +
                             std::string(kOidChipIdBinding) + ") not found in cert");
    }
    X509_EXTENSION* ext = X509_get_ext(cert, idx);
    if (!ext) throw TeeAnchorError("X509_get_ext returned null");
    const ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
    if (!data) throw TeeAnchorError("X509_EXTENSION_get_data returned null");

    return decode_chip_id_binding(ASN1_STRING_get0_data(data),
                                  static_cast<size_t>(ASN1_STRING_length(data)));
}

}  // namespace tee_anchor::binding

//
// cca_provision.cpp
//
// CCA Attestation Token (RATS CCA token v01, CBOR tag 399) の Platform Token を
// pin した CPAK で検証し instance-id を取り出す。CBOR/COSE は common/cbor.hpp の
// 最小実装で扱い、ECDSA(P-384/SHA-384=ES384) 検証は OpenSSL で行う。
//
#include "cca_provision.hpp"

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include "cbor.hpp"
#include "error.hpp"
#include "io.hpp"
#include "openssl_raii.hpp"

#include "cca_cpak_pubkey.hpp"

namespace tee_anchor::cca {

namespace {

// CBOR/COSE のキー・タグ定数。
constexpr uint64_t kCcaTokenTag      = 399;    // RATS CCA token v01 (EAT collection)
constexpr uint64_t kCoseSign1Tag     = 18;     // COSE_Sign1
constexpr int64_t  kPlatformTokenKey = 44234;  // cca-platform-token
constexpr int64_t  kInstanceIdKey    = 256;    // cca-platform-instance-id (UEID)
constexpr int64_t  kImplIdKey        = 2396;   // cca-platform-implementation-id
constexpr int64_t  kCoseAlgKey       = 1;      // COSE protected header: alg
constexpr int64_t  kCoseAlgES384     = -35;    // ECDSA w/ SHA-384

using EcdsaSigPtr = std::unique_ptr<ECDSA_SIG, Deleter<ECDSA_SIG_free>>;
using MdCtxPtr    = std::unique_ptr<EVP_MD_CTX, Deleter<EVP_MD_CTX_free>>;

// COSE の生署名 (r||s, 各 48B) を DER に直して ES384 で検証する。
bool verify_es384(EVP_PKEY* pk, const std::vector<uint8_t>& msg,
                  const std::vector<uint8_t>& raw_sig) {
    if (raw_sig.size() != 96) {
        throw TeeAnchorError("CCA: unexpected COSE signature length "
                             "(expected 96 bytes for ES384/P-384)");
    }
    BnPtr r(BN_bin2bn(raw_sig.data(),      48, nullptr));
    BnPtr s(BN_bin2bn(raw_sig.data() + 48, 48, nullptr));
    if (!r || !s) throw_openssl_error("BN_bin2bn (COSE signature)");

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

    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) throw_openssl_error("EVP_MD_CTX_new");
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha384(), nullptr, pk) != 1) {
        throw_openssl_error("EVP_DigestVerifyInit (ES384)");
    }
    const int rc = EVP_DigestVerify(ctx.get(), der.data(), der.size(),
                                    msg.data(), msg.size());
    if (rc < 0) throw_openssl_error("EVP_DigestVerify");
    return rc == 1;
}

const cbor::Value& expect_bytes(const cbor::Value& v, const char* what) {
    if (v.type != cbor::Type::Bytes) throw TeeAnchorError(std::string("CCA: ") + what + " is not a byte string");
    return v;
}

}  // namespace

CcaVerifyResult verify_and_extract(const std::string& token_path) {
    const std::vector<uint8_t> tok = read_file(token_path);

    // 1. 最上位: tag(399) で包まれた map。
    cbor::Decoder dec(tok.data(), tok.size());
    cbor::Value top = dec.decode();
    const cbor::Value& coll = top.untag(kCcaTokenTag);
    if (coll.type != cbor::Type::Map) {
        throw TeeAnchorError("CCA: token top-level is not a CCA collection map "
                             "(expected CBOR tag 399)");
    }

    // 2. Platform Token を取り出す（値は COSE_Sign1 を内包した byte string）。
    const cbor::Value* plat = coll.at(kPlatformTokenKey);
    if (!plat) throw TeeAnchorError("CCA: cca-platform-token (key 44234) not found");
    const std::vector<uint8_t>& plat_bytes = expect_bytes(*plat, "platform token").bytes;

    // 3. COSE_Sign1 = tag(18) array[ protected:bstr, unprotected, payload:bstr, sig:bstr ]
    cbor::Decoder pdec(plat_bytes.data(), plat_bytes.size());
    cbor::Value sign1 = pdec.decode();
    const cbor::Value& arr = sign1.untag(kCoseSign1Tag);
    if (arr.type != cbor::Type::Array || arr.array.size() != 4) {
        throw TeeAnchorError("CCA: platform token is not a COSE_Sign1 (tag18/array[4])");
    }
    const std::vector<uint8_t>& protected_b = expect_bytes(arr.array[0], "COSE protected header").bytes;
    const std::vector<uint8_t>& payload_b   = expect_bytes(arr.array[2], "COSE payload").bytes;
    const std::vector<uint8_t>& sig_b       = expect_bytes(arr.array[3], "COSE signature").bytes;

    // 3a. alg が ES384(-35) であることを確認（protected header の map{1:-35}）。
    {
        cbor::Decoder hdec(protected_b.data(), protected_b.size());
        cbor::Value ph = hdec.decode();
        const cbor::Value* alg = (ph.type == cbor::Type::Map) ? ph.at(kCoseAlgKey) : nullptr;
        if (!alg || alg->as_int() != kCoseAlgES384) {
            throw TeeAnchorError("CCA: unexpected COSE alg (expected ES384=-35)");
        }
    }

    // 4. Sig_structure = [ "Signature1", protected:bstr, external_aad:bstr(空), payload:bstr ]
    std::vector<uint8_t> sig_structure;
    cbor::enc_head(sig_structure, 4, 4);                 // array(4)
    cbor::enc_text(sig_structure, "Signature1");
    cbor::enc_bytes(sig_structure, protected_b.data(), protected_b.size());
    cbor::enc_bytes(sig_structure, nullptr, 0);          // external_aad = b""
    cbor::enc_bytes(sig_structure, payload_b.data(), payload_b.size());

    // 5. pin した CPAK で署名検証。
    EvpPkeyPtr cpak = load_pinned_cpak();
    if (!verify_es384(cpak.get(), sig_structure, sig_b)) {
        throw TeeAnchorError("CCA: platform token signature verification failed "
                             "(CPAK pin mismatch or tampered token)");
    }

    // 6. payload(claims) から instance-id を抽出。
    cbor::Decoder cdec(payload_b.data(), payload_b.size());
    cbor::Value claims = cdec.decode();
    if (claims.type != cbor::Type::Map) {
        throw TeeAnchorError("CCA: platform claims payload is not a map");
    }
    const cbor::Value* iid = claims.at(kInstanceIdKey);
    if (!iid || iid->type != cbor::Type::Bytes || iid->bytes.empty()) {
        throw TeeAnchorError("CCA: cca-platform-instance-id (claim 256) missing/empty");
    }

    CcaVerifyResult res;
    res.instance_id = iid->bytes;
    const cbor::Value* impl = claims.at(kImplIdKey);
    if (impl && impl->type == cbor::Type::Bytes) res.implementation_id = impl->bytes;
    res.cpak = std::move(cpak);
    return res;
}

}  // namespace tee_anchor::cca

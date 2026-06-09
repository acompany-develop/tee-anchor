//
// tdx_provision.cpp
//
// Phase 2 / TDX:
//   TD Quote から PCK 証明書チェーンを抽出 → Intel SGX Root CA(公開鍵ハードコード)
//   でチェーン検証 → 検証通過後に PPID を抽出する。
//
// SGX(v3) との差は TD Quote のバイナリ構造のみ。チェーン検証(verify_pck_chain)と
// PPID 抽出(find_sgx_extension_octet)は SGX 実装をそのまま再利用する。詳細は
// tdx_provision.hpp の方針コメントを参照。
//
#include "tdx_provision.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include <openssl/err.h>
#include <openssl/pem.h>

#include "error.hpp"
#include "sgx/sgx_provision.hpp"

namespace tee_anchor::tdx {

namespace {

// ---- TD Quote バイナリのレイアウト ----------------------------------------
//  共通 Header(48): version(u16) | att_key_type(u16) | tee_type(u32) | ...
//  v4: Header(48) | TD report body(固定 N) | sig_len(u32) | sig_data
//  v5: Header(48) | body_type(u16) | body_size(u32) | body | sig_len(u32) | sig_data
//
//  sig_data: sig(64) | attest_pub_key(64) | cert_data(type=6) { ... cert_data(type=5) }
constexpr size_t kHeaderSize     = 48;
constexpr size_t kSigPubkeySize  = 64 + 64;  // ECDSA sig + attestation pubkey
constexpr size_t kCertHdrSize    = 6;         // cert_data: type(u16) + size(u32)
constexpr size_t kQeReportSize   = 384;       // type=6 body 先頭の QE Report
constexpr size_t kQeReportSig    = 64;
constexpr uint16_t kCertTypeQeReport = 6;     // QE_REPORT_CERTIFICATION_DATA
constexpr uint16_t kCertTypePck      = 5;     // PCK_CERT_CHAIN

// v4 の TD report body サイズ。v4 は常に TD report 1.0 (584 バイト) を運ぶ。
// (TD report 1.5 は v5 で body_type=3 として運ばれ、v4 には現れない。
//  Humane-RAFW-TDX も v4 を report_base=48 固定で扱っており body 長は不変。)
constexpr size_t kTdReportBodyV4 = 584;

void need(const std::vector<uint8_t>& q, size_t off, size_t n, const char* what) {
    if (off > q.size() || n > q.size() - off) {
        throw TeeAnchorError(std::string("TD quote too short while reading ") + what);
    }
}

uint16_t rd_u16le(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}
uint32_t rd_u32le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

// signature_data 内の二重ネスト(type=6 → type=5)を辿り、内側 PCK チェーン(PEM)の
// [offset, size] を返す。構造が想定どおりでなければ nullopt(候補不一致 / 破損)。
//
//   sd, sdl: signature_data の開始オフセットと長さ
//
// 整合性チェック: 外側 type=6 の本体終端が signature_data の終端と一致し、
//                内側 type=5 の本体終端も同じ位置で閉じることを要求する。
std::optional<std::pair<size_t, size_t>>
locate_pck_region(const std::vector<uint8_t>& q, size_t sd, size_t sdl) {
    // signature_data がバッファに収まるか
    if (sd > q.size() || sdl > q.size() - sd) return std::nullopt;
    const size_t sd_end = sd + sdl;

    // 外側 cert_data ヘッダ(type=6)
    const size_t outer_hdr = sd + kSigPubkeySize;
    if (outer_hdr + kCertHdrSize > sd_end) return std::nullopt;
    const uint16_t outer_type = rd_u16le(&q[outer_hdr]);
    const uint32_t outer_size = rd_u32le(&q[outer_hdr + 2]);
    const size_t outer_body = outer_hdr + kCertHdrSize;
    if (outer_type != kCertTypeQeReport) return std::nullopt;
    if (outer_size > sd_end - outer_body) return std::nullopt;
    const size_t outer_end = outer_body + outer_size;
    if (outer_end != sd_end) return std::nullopt;  // 自己整合性

    // 外側 body: qe_report(384) | qe_report_sig(64) | qe_auth_data(u16 size + bytes)
    //            | 内側 cert_data(type=5)
    size_t p = outer_body + kQeReportSize + kQeReportSig;
    if (p + 2 > outer_end) return std::nullopt;
    const uint16_t auth_size = rd_u16le(&q[p]);
    p += 2;
    if (auth_size > outer_end - p) return std::nullopt;
    p += auth_size;

    // 内側 cert_data ヘッダ(type=5)
    if (p + kCertHdrSize > outer_end) return std::nullopt;
    const uint16_t inner_type = rd_u16le(&q[p]);
    const uint32_t inner_size = rd_u32le(&q[p + 2]);
    const size_t inner_body = p + kCertHdrSize;
    if (inner_type != kCertTypePck) return std::nullopt;
    if (inner_size > outer_end - inner_body) return std::nullopt;
    if (inner_body + inner_size != outer_end) return std::nullopt;  // 末尾まで閉じる

    return std::make_pair(inner_body, static_cast<size_t>(inner_size));
}

// version を読んで signature_data の [offset, length] を決める。
std::pair<size_t, size_t> locate_sig_data(const std::vector<uint8_t>& q) {
    need(q, 0, kHeaderSize, "quote header");
    const uint16_t version  = rd_u16le(&q[0]);
    const uint32_t tee_type = rd_u32le(&q[4]);

    // TDX の tee_type は 0x81。SGX(0x00) の Quote が誤って渡された場合に明示エラー。
    if (tee_type != 0x00000081u) {
        throw TeeAnchorError(
            "TD quote has unexpected tee_type=0x" +
            [&]{ char b[16]; std::snprintf(b, sizeof b, "%08x", tee_type); return std::string(b); }() +
            " (expected 0x00000081 = TDX); use --tee-type sgx for SGX quotes");
    }

    if (version == 4) {
        // v4: Header(48) | TD report body(584 固定) | sig_len(u32) | sig_data
        const size_t len_off = kHeaderSize + kTdReportBodyV4;
        need(q, len_off, 4, "v4 sig_len");
        const uint32_t sdl = rd_u32le(&q[len_off]);
        const size_t sd = len_off + 4;
        if (!locate_pck_region(q, sd, sdl)) {
            throw TeeAnchorError(
                "v4 TD quote signature_data structure is not as expected "
                "(outer cert type!=6 or inner cert type!=5)");
        }
        return {sd, sdl};
    }

    if (version == 5) {
        // v5: Header(48) | body_type(u16) | body_size(u32) | body | sig_len(u32) | sig_data
        // body 長が明示されるので、それを読んで signature_data の位置を決める
        // (v4 の report_base=48 に対し v5 は +6 = report_base=54。Humane-RAFW-TDX と同じ)。
        need(q, kHeaderSize, kCertHdrSize, "v5 body descriptor");
        const uint32_t body_size = rd_u32le(&q[kHeaderSize + 2]);
        const size_t len_off = kHeaderSize + kCertHdrSize + body_size;
        need(q, len_off, 4, "v5 sig_len");
        const uint32_t sdl = rd_u32le(&q[len_off]);
        const size_t sd = len_off + 4;
        if (!locate_pck_region(q, sd, sdl)) {
            throw TeeAnchorError(
                "v5 TD quote signature_data structure is not as expected "
                "(outer cert type!=6 or inner cert type!=5)");
        }
        return {sd, sdl};
    }

    throw TeeAnchorError(
        "unsupported TD quote version=" + std::to_string(version) +
        " (supported: 4, 5)");
}

}  // namespace

std::vector<X509Ptr>
extract_pck_chain_from_quote(const std::vector<uint8_t>& quote) {
    const auto [sd, sdl] = locate_sig_data(quote);
    const auto region = locate_pck_region(quote, sd, sdl);
    if (!region) {
        // locate_sig_data が成功していれば region も成功するはずだが、防御的に。
        throw TeeAnchorError("PCK cert chain not found in TD quote certification data");
    }
    const auto [pck_off, pck_size] = *region;

    BioPtr bio(BIO_new_mem_buf(quote.data() + pck_off, static_cast<int>(pck_size)));
    if (!bio) throw_openssl_error("BIO_new_mem_buf");

    std::vector<X509Ptr> chain;
    while (true) {
        X509* raw = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
        if (!raw) break;
        chain.emplace_back(raw);
    }
    ERR_clear_error();  // 末尾の EOF 失敗をクリア

    if (chain.empty()) {
        throw TeeAnchorError("no PCK certificates found in TD quote certification data");
    }
    return chain;
}

std::vector<uint8_t> extract_ppid_from_quote(const std::vector<uint8_t>& quote) {
    auto chain = extract_pck_chain_from_quote(quote);
    X509* leaf = sgx::verify_pck_chain(chain);  // 同じ Intel SGX Root CA / PCK チェーン
    auto ppid = sgx::find_sgx_extension_octet(leaf, sgx::OID_SGX_PPID);
    if (!ppid) {
        throw TeeAnchorError("PPID (OID " + std::string(sgx::OID_SGX_PPID) +
                             ") not found in PCK leaf");
    }
    return *ppid;
}

}  // namespace tee_anchor::tdx

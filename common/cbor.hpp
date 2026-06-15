#pragma once
//
// 最小 CBOR (RFC 8949) デコーダ / エンコーダ。
//
// TEE Anchor は他 TEE では OpenSSL のみで自己完結しており、CCA のためだけに
// QCBOR/libcbor 等のビルド依存を増やしたくない。CCA Attestation Token は
//   - 最上位: tag(399) で包まれた map (definite length)
//   - 各 token: tag(18) COSE_Sign1 = array[ protected:bstr, unprotected:map,
//                                            payload:bstr, signature:bstr ]
//   - claims: 整数キーの map
// という固定的で単純な形しか出てこないため、それを読むのに必要十分な範囲だけを
// 実装する（indefinite length / float / bignum などは非対応で、出てきたら例外）。
//
// COSE_Sign1 の署名検証には Sig_structure を再エンコードする必要があるため、
// bstr / text / array / 整数 head の最小エンコーダも用意する。
//
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "error.hpp"

namespace tee_anchor::cbor {

enum class Type { Uint, Nint, Bytes, Text, Array, Map, Tag, Simple };

struct Value {
    Type type = Type::Uint;
    uint64_t uint = 0;                              // Uint / Nint(生値) / Simple / Tag番号
    std::vector<uint8_t> bytes;                     // Bytes
    std::string text;                               // Text
    std::vector<Value> array;                       // Array（Tag の中身は array[0]）
    std::vector<std::pair<Value, Value>> map;       // Map

    int64_t as_int() const {
        if (type == Type::Uint) return static_cast<int64_t>(uint);
        if (type == Type::Nint) return -1 - static_cast<int64_t>(uint);
        throw TeeAnchorError("cbor: value is not an integer");
    }
    // 整数キーで map を引く（無ければ nullptr）。
    const Value* at(int64_t key) const {
        for (const auto& kv : map) {
            if ((kv.first.type == Type::Uint || kv.first.type == Type::Nint) &&
                kv.first.as_int() == key) {
                return &kv.second;
            }
        }
        return nullptr;
    }
    // Tag(=expected) を剥がして中身を返す。Tag でなければそのまま返す。
    const Value& untag(uint64_t expected) const {
        if (type == Type::Tag) {
            if (uint != expected) throw TeeAnchorError("cbor: unexpected tag number");
            if (array.empty())    throw TeeAnchorError("cbor: empty tag content");
            return array[0];
        }
        return *this;
    }
};

class Decoder {
public:
    Decoder(const uint8_t* p, size_t n) : p_(p), end_(p + n) {}
    Value decode() { return read_item(); }

private:
    const uint8_t* p_;
    const uint8_t* end_;

    uint8_t rb() {
        if (p_ >= end_) throw TeeAnchorError("cbor: truncated input");
        return *p_++;
    }
    void need(uint64_t n) const {
        if (static_cast<uint64_t>(end_ - p_) < n) throw TeeAnchorError("cbor: truncated item");
    }
    uint64_t read_len(uint8_t ai) {
        if (ai < 24) return ai;
        if (ai == 24) return rb();
        if (ai == 25) { uint64_t v = rb(); v = (v << 8) | rb(); return v; }
        if (ai == 26) { uint64_t v = 0; for (int i = 0; i < 4; ++i) v = (v << 8) | rb(); return v; }
        if (ai == 27) { uint64_t v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | rb(); return v; }
        throw TeeAnchorError("cbor: indefinite/reserved length not supported");
    }
    Value read_item() {
        const uint8_t ib = rb();
        const uint8_t mt = ib >> 5;
        const uint8_t ai = ib & 0x1f;
        Value v;
        switch (mt) {
            case 0: v.type = Type::Uint; v.uint = read_len(ai); return v;
            case 1: v.type = Type::Nint; v.uint = read_len(ai); return v;
            case 2: {
                v.type = Type::Bytes; uint64_t n = read_len(ai); need(n);
                v.bytes.assign(p_, p_ + n); p_ += n; return v;
            }
            case 3: {
                v.type = Type::Text; uint64_t n = read_len(ai); need(n);
                v.text.assign(reinterpret_cast<const char*>(p_), static_cast<size_t>(n)); p_ += n; return v;
            }
            case 4: {
                v.type = Type::Array; uint64_t n = read_len(ai);
                v.array.reserve(static_cast<size_t>(n));
                for (uint64_t i = 0; i < n; ++i) v.array.push_back(read_item());
                return v;
            }
            case 5: {
                v.type = Type::Map; uint64_t n = read_len(ai);
                v.map.reserve(static_cast<size_t>(n));
                for (uint64_t i = 0; i < n; ++i) {
                    Value k = read_item(); Value val = read_item();
                    v.map.emplace_back(std::move(k), std::move(val));
                }
                return v;
            }
            case 6: {
                v.type = Type::Tag; v.uint = read_len(ai);
                v.array.push_back(read_item()); return v;
            }
            case 7: {
                // simple/float。CCA token では使われない想定。simple値のみ許容。
                if (ai == 24) { v.type = Type::Simple; v.uint = rb(); return v; }
                if (ai < 24)  { v.type = Type::Simple; v.uint = ai;   return v; }
                throw TeeAnchorError("cbor: float/break not supported");
            }
        }
        throw TeeAnchorError("cbor: invalid major type");
    }
};

// ---- 最小エンコーダ（COSE Sig_structure 構築に必要な分だけ）-------------------
inline void enc_head(std::vector<uint8_t>& o, uint8_t mt, uint64_t n) {
    const uint8_t b = static_cast<uint8_t>(mt << 5);
    if (n < 24)        { o.push_back(b | static_cast<uint8_t>(n)); }
    else if (n < 256)  { o.push_back(b | 24); o.push_back(static_cast<uint8_t>(n)); }
    else if (n < 65536){ o.push_back(b | 25); o.push_back(static_cast<uint8_t>(n >> 8)); o.push_back(static_cast<uint8_t>(n)); }
    else               { o.push_back(b | 26); for (int i = 3; i >= 0; --i) o.push_back(static_cast<uint8_t>(n >> (8 * i))); }
}
inline void enc_bytes(std::vector<uint8_t>& o, const uint8_t* d, size_t n) {
    enc_head(o, 2, n); if (n) o.insert(o.end(), d, d + n);
}
inline void enc_text(std::vector<uint8_t>& o, const std::string& s) {
    enc_head(o, 3, s.size()); o.insert(o.end(), s.begin(), s.end());
}

}  // namespace tee_anchor::cbor

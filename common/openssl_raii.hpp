#pragma once
//
// OpenSSL 生ポインタの RAII ラッパ。本プロジェクトの規約として、
// OpenSSL オブジェクトは必ずこれらの unique_ptr で包む。
//
#include <memory>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace tee_anchor {

template <auto Fn>
struct Deleter {
    template <class T>
    void operator()(T* p) const noexcept { Fn(p); }
};

using X509Ptr         = std::unique_ptr<X509,             Deleter<X509_free>>;
using X509ReqPtr      = std::unique_ptr<X509_REQ,         Deleter<X509_REQ_free>>;
using EvpPkeyPtr      = std::unique_ptr<EVP_PKEY,         Deleter<EVP_PKEY_free>>;
using EvpPkeyCtxPtr   = std::unique_ptr<EVP_PKEY_CTX,     Deleter<EVP_PKEY_CTX_free>>;
using BioPtr          = std::unique_ptr<BIO,              Deleter<BIO_free_all>>;
using X509StorePtr    = std::unique_ptr<X509_STORE,       Deleter<X509_STORE_free>>;
using X509StoreCtxPtr = std::unique_ptr<X509_STORE_CTX,   Deleter<X509_STORE_CTX_free>>;
using X509CrlPtr      = std::unique_ptr<X509_CRL,         Deleter<X509_CRL_free>>;
using Asn1OctStrPtr   = std::unique_ptr<ASN1_OCTET_STRING, Deleter<ASN1_OCTET_STRING_free>>;
using Asn1ObjectPtr   = std::unique_ptr<ASN1_OBJECT,      Deleter<ASN1_OBJECT_free>>;
using Asn1IntPtr      = std::unique_ptr<ASN1_INTEGER,     Deleter<ASN1_INTEGER_free>>;
using X509NamePtr     = std::unique_ptr<X509_NAME,        Deleter<X509_NAME_free>>;
using X509ExtPtr      = std::unique_ptr<X509_EXTENSION,   Deleter<X509_EXTENSION_free>>;
using BnPtr           = std::unique_ptr<BIGNUM,           Deleter<BN_free>>;

// sk_X509_free 等は OpenSSL のマクロ展開で関数ポインタが取れないため、
// 個別の deleter ファンクタを用意する。
struct SkX509Free {
    void operator()(STACK_OF(X509)* s) const noexcept { sk_X509_free(s); }
};
using SkX509Ptr = std::unique_ptr<STACK_OF(X509), SkX509Free>;

}  // namespace tee_anchor

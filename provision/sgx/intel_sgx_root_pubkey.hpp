#pragma once
//
// Intel SGX Root CA の公開鍵（信頼アンカー）。
//
// 出典: Intel DCAP QvE (qve.cpp) の INTEL_ROOT_PUB_KEY。
//   https://github.com/intel/confidential-computing.tee.dcap/blob/
//     dcap_1.19_reproducible/QuoteVerification/QvE/Enclave/qve.cpp#L94
//
// 形式: EC P-256 公開鍵を SEC1 uncompressed point 形式で並べたもの
//       (0x04 || X(32 バイト) || Y(32 バイト) = 65 バイト)。
//
// 確認: DCAP QvE のハードコード値と完全一致。
//       かつ、provision/sgx/sgx_sample で実機生成した Quote から取り出した
//       チェーン末尾の自己署名証明書(subject == issuer == "Intel SGX Root CA")
//       の公開鍵とも bit-for-bit 一致することを確認済み。
//
// 設計意図: 信頼根は「証明書」ではなく「公開鍵」に置く。証明書には有効期限や
//           シリアルなど偶発的な属性が付くが、公開鍵自体は Intel が同一鍵で
//           証明書を再発行しても不変。よって Quote 同梱の root 証明書の
//           公開鍵がここに一致するかだけを検査し、一致したらその root 証明書を
//           信頼アンカーとして OpenSSL の X509_STORE に投入する。
//
#include <array>
#include <cstdint>

namespace tee_anchor::sgx {

inline constexpr std::array<uint8_t, 65> kIntelSgxRootPubkey = {
    0x04, 0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61, 0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c,
    0xda, 0x10, 0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4, 0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70,
    0x55, 0x25, 0xf5, 0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4, 0x0d, 0x86, 0x0b, 0xd0, 0xcc,
    0x4e, 0xe2, 0x6a, 0xac, 0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55, 0x8c, 0x45, 0x3f, 0x6b,
    0x09, 0x04, 0xae, 0x73, 0x94,
};

}  // namespace tee_anchor::sgx

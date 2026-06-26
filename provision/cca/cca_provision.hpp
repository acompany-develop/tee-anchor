#pragma once
//
// Arm CCA provision: CCA Attestation Token (CBOR/COSE) を読み、pin した CPAK 公開鍵で
// Platform Token (COSE_Sign1 / ES384) の署名を検証し、通過後に
// cca-platform-instance-id（= Chip ID）を抽出する。
//
// 他 TEE との対称性:
//   SGX/TDX: Quote 内蔵の PCK チェーンを Intel root pubkey で検証 → PPID 抽出
//   SEV-SNP: Report + VCEK チェーンを ARK pin + 自前検証 → CHIP_ID 抽出
//   Arm CCA: Platform Token を CPAK pin で検証 → instance-id 抽出
//
// CCA には X.509 が無いため、endorsement の Subject Public Key には CPAK
// (= instance-id が指す Platform Attestation Key) を流用する（SGX の PCK leaf /
// SNP の VCEK leaf 公開鍵を流用するのと同じ位置づけ）。
//
#include <cstdint>
#include <string>
#include <vector>

#include "openssl_raii.hpp"

namespace tee_anchor::cca {

struct CcaVerifyResult {
    std::vector<uint8_t> instance_id;        // cca-platform-instance-id (claim 256) = Chip ID
    std::vector<uint8_t> implementation_id;  // cca-platform-implementation-id (claim 2396) 参考
    EvpPkeyPtr           cpak;               // 検証に用いた CPAK（endorsement Subject pubkey）
};

// token をロードし CPAK pin で Platform Token を検証 → instance-id を抽出する。
// 署名検証失敗・構造不正・instance-id 欠落時は TeeAnchorError。
CcaVerifyResult verify_and_extract(const std::string& token_path);

}  // namespace tee_anchor::cca

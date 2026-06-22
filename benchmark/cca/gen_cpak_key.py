#!/usr/bin/env python3
"""gen_cpak_key.py — CCA ベンチ用 CPAK 公開鍵 (cpak.jwk / cpak.pem) を生成する。

bench_cca.sh の従来 RA ベースライン `evcli cca check -k <cpak.jwk>` には、
CCA Platform Token (COSE_Sign1) の署名検証鍵 = CPAK 公開鍵を JWK で渡す必要がある。
TEE Anchor 側は同じ CPAK をコードに pin しているが (provision/cca/cca_cpak_pubkey.hpp)、
evcli は外部入力で鍵を要求するため、その pin と同一の鍵をここで JWK/PEM 化する。

このバイト列は QEMU フルエミュレーション環境の固定 dev CPAK
(P-384, ES384, SPKI DER 120 bytes) で、tee-anchor の cca_cpak_pubkey.hpp の
kCpakSpkiDer と一致する。実 HW では CPAK は CoRIM endorsement で配布されるため、
本スクリプトは PoC (QEMU) 専用。

使い方:
    python3 gen_cpak_key.py [出力ディレクトリ]   # 既定: ~/cca_verify_bundle
"""
import base64
import os
import sys

# provision/cca/cca_cpak_pubkey.hpp の kCpakSpkiDer と同一 (P-384 SPKI DER, 120B)
CPAK_SPKI_DER = bytes([
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
    0x21, 0x28, 0x67, 0xc5, 0x2e, 0x2b, 0x95, 0x08, 0xb0, 0xa4, 0x20, 0xa9,
    0x05, 0x60, 0xf3, 0x94, 0xd2, 0xdf, 0xaa, 0x21, 0xbd, 0xd7, 0x51, 0x4f,
    0xf1, 0xa9, 0x01, 0xaf, 0xe7, 0xe1, 0xf7, 0x8b, 0xb1, 0x1d, 0x4e, 0x66,
    0xf8, 0xa8, 0xa3, 0x8a, 0xfa, 0x76, 0xaf, 0x6a, 0x31, 0xc4, 0xde, 0x8c,
    0x84, 0xce, 0x2d, 0xaf, 0xc9, 0x96, 0x42, 0x58, 0xb5, 0x3f, 0xad, 0x71,
    0x87, 0x74, 0xf4, 0x56, 0x20, 0xd1, 0x11, 0xb1, 0x76, 0xe8, 0x31, 0x8e,
    0x11, 0x87, 0xdb, 0x02, 0x35, 0xa3, 0x18, 0xd3, 0x7b, 0xa5, 0x97, 0xfe,
    0xe8, 0x0e, 0x0e, 0x4c, 0x76, 0x2a, 0x12, 0xbc, 0xb3, 0xea, 0x6e, 0xd4,
])


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def main() -> None:
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/cca_verify_bundle")
    os.makedirs(out_dir, exist_ok=True)

    assert len(CPAK_SPKI_DER) == 120, len(CPAK_SPKI_DER)
    # SPKI 末尾 97B = 非圧縮点 0x04 || X(48) || Y(48)
    point = CPAK_SPKI_DER[-97:]
    assert point[0] == 0x04, point[0]
    x, y = point[1:49], point[49:97]

    jwk = (
        '{\n'
        '  "kty": "EC",\n'
        '  "crv": "P-384",\n'
        '  "alg": "ES384",\n'
        f'  "x": "{b64url(x)}",\n'
        f'  "y": "{b64url(y)}"\n'
        '}\n'
    )
    jwk_path = os.path.join(out_dir, "cpak.jwk")
    with open(jwk_path, "w") as f:
        f.write(jwk)

    b64 = base64.b64encode(CPAK_SPKI_DER).decode()
    pem = ("-----BEGIN PUBLIC KEY-----\n"
           + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
           + "\n-----END PUBLIC KEY-----\n")
    pem_path = os.path.join(out_dir, "cpak.pem")
    with open(pem_path, "w") as f:
        f.write(pem)

    print(f"wrote {jwk_path}")
    print(f"wrote {pem_path}")


if __name__ == "__main__":
    main()

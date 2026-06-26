# SEV-SNP Attestation Report 取得サンプル

TEE Anchor の `provision` / `verify`（SEV-SNP 経路）に渡す **`report.bin` と VCEK
証明書チェーンを実機で生成する**ためのサンプル。SGX 版
（`provision/sgx/sgx_sample`）の SEV-SNP 対応版にあたる。

> このサンプルは TEE Anchor 本体（Endorser/Verifier）の一部ではなく、
> **評価用に Attester 側の入力を作るためのハーネス**です。本体は Report と
> 証明書をファイル入力として消費するだけで、SNP デバイスには触れません。

SGX と異なり Enclave 実装が不要なため、[snpguest](https://github.com/virtee/snpguest)
を使ったシェルスクリプト 1 本で完結する。

## 構成

```
snp-sample/
├── get_attestation.sh    # 一括実行スクリプト
└── README.md
```

## 前提（実機側）

- AMD SEV-SNP ゲスト（`/dev/sev-guest` が存在すること）。GCP / Azure の
  Confidential VM 等。
- AMD KDS（`kds.amd.com`）への外向き HTTPS 接続。
- Report 取得（`/dev/sev-guest` の ioctl）に sudo 権限。

## 実行

```sh
./get_attestation.sh
```

スクリプトの流れ：

1. **snpguest の確保**: PATH → `~/snpguest/target/release/snpguest` の順に探し、
   無ければ **y/N 確認の上で** `~/snpguest` に最新版（main）をクローンしてビルドする
   （Rust toolchain が無ければ rustup で導入。いずれもユーザ領域のみ）。
2. **Attestation Report 取得**: 64B のランダム request data 付きで
   `report.bin` を生成（ここだけ sudo）。
3. **証明書チェーン取得**: Report に基づき AMD KDS から
   `certs/ark.pem`（root）/ `certs/ask.pem`（intermediate）/ `certs/vcek.pem`（leaf）
   を取得。
4. **sanity check**: `snpguest verify certs` / `verify attestation` で
   取得物の整合性を確認。

## オプション（環境変数で上書き）

| 変数 | 既定 | 説明 |
|---|---|---|
| `SNP_VMPL` | （snpguest 既定 = 1） | Report 要求の VMPL |
| `SNP_PROCESSOR_MODEL` | （Report から自動導出） | KDS 問い合わせのプロセッサ世代（`milan` / `genoa` / `turin` 等）。Report version が 2 以前で自動導出に失敗する場合に明示する |

## 生成物

| ファイル | 役割 |
|---|---|
| `report.bin` | Attestation Report（TEE Anchor への入力。SGX の `quote.dat` に相当） |
| `request-data.txt` | Report 要求に使った 64B request data（参照用） |
| `certs/ark.pem` | AMD Root Key（自己署名 root） |
| `certs/ask.pem` | AMD SEV Key（intermediate） |
| `certs/vcek.pem` | VCEK（leaf。**CHIP_ID を拡張に含む** — TEE Anchor の binding 対象） |

> SGX では Quote 内に PCK 証明書チェーンが内包される（cert key type 5）が、
> SEV-SNP の Report には VCEK チェーンが含まれないため、KDS から別途取得した
> `certs/` を Report と併せて TEE Anchor に渡す形になる。

## TEE Anchor の SNP provision での使われ方

`tee-anchor provision --tee-type snp` は、ここで生成した `report.bin` と `certs/`
を入力に取り、**ベンダー検証（ARK→ASK→VCEK チェーン検証 + VCEK による Report 署名検証）を
OpenSSL でインプロセス実行**する。SGX/TDX/CCA と同じく、実行時に外部ツール snpguest は
不要（snpguest は上記の証拠生成にのみ使う）。

```sh
tee-anchor provision --tee-type snp \
    --report report.bin --certs certs \
    --ca-key ca.key --ca-cert ca.crt --out snp_endorsement.crt
```

- 信頼根（AMD ARK）は **コードにハードコードした既知値**（Milan/Genoa/Turin の公開鍵
  SHA-384）に pin 照合し、一致した ARK のみを信頼アンカーとして採用する。これで SGX と
  同じ「信頼根はコードが握る」プロパティを保つ。
- 検証フロー: Report ヘッダ検証 → ARK pin 照合 → pin した ARK を信頼根に
  `X509_verify_cert` で ARK→ASK→VCEK チェーン検証 → VCEK 公開鍵で Report 署名
  （`0x0–0x29F` の ECDSA-P384/SHA-384）を検証 → 通過後に Report 0x1A0 から CHIP_ID(64B) を抽出。

`tee-anchor verify --tee-type snp` も同じ証拠（`report.bin` + `certs/`）を取り、上記の検証
通過後に組織 endorsement chain 検証と Chip ID 照合を行う（exit code は SGX と共通:
0/20/21/22/24/30）。`verify` も snpguest 不要。

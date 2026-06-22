# TEE Anchor ベンチマーク

SGX/TDX/SNP/CCA 横断の TEE Anchor について、**「従来 RA 検証器」と「TEE Anchor 検証
（組織 endorsement chain + Chip ID 照合）」のコスト差**を計測するためのスクリプト集。

| TEE | 従来 RA ベースライン | TEE Anchor | 計測手段 |
|-----|---------------------|-----------|----------|
| SEV-SNP | `snpguest verify` | `tee-anchor verify --tee-type snp` | `hyperfine` (`snp/bench_snp.sh`) |
| Arm CCA | `evcli cca check` | `tee-anchor verify --tee-type cca` | `hyperfine` (`cca/bench_cca.sh`) |
| Intel TDX | DCAP QVL (`verify_quote` + appraise) | `tee-anchor verify --tee-type tdx` | in-process ループ計測 (`tdx/rp_client.py`) |
| Intel SGX (MAA) | MAA への Quote 送信 + JWT/Enclave 検証 | `tee-anchor verify --tee-type sgx` | in-process ループ計測 (`sgx/client_app.cpp`) |

> 各スクリプトは `tee-anchor` バイナリ（リポジトリ直下でビルドしたもの）を呼ぶ。
> `TEE_ANCHOR=<path>` で明示指定可。未指定時は `../../tee-anchor` と `~/Develop/tee-anchor/tee-anchor` を探索。

---

## 構成

```
benchmark/
├── README.md
├── snp/bench_snp.sh        SNP: snpguest vs tee-anchor (hyperfine A/B)
├── cca/bench_cca.sh        CCA: evcli vs tee-anchor (hyperfine A/B)
├── cca/gen_cpak_key.py     CCA: pin 済み CPAK → cpak.jwk/pem を生成 (evcli 入力用)
├── tdx/rp_client.py        TDX: Humane-RAFW-TDX の RP に A/B 計測を統合した版 (MIT, Acompany)
├── sgx/client_app.cpp      SGX(MAA) verify: Humane-RAFW-MAA の Client_App に A/B 計測を統合した版 (Acompany)
├── sgx/bench_ca_init.sh    ca-init 計測 (TEE 非依存。曲線 P-256/384/521 比較)
└── sgx/bench_provision.sh  SGX provision 計測 (Quote→endorsement 発行)
```

> **コマンドごとの分割**: `verify` だけでなく `ca-init` / `provision`（発行側）も計測
> 対象。各 TEE フォルダ内で**コマンド単位**にスクリプトを分ける方針とする。
> `provision` は TEE 依存（入力が SGX/TDX=Quote, SNP=report, CCA=token）なので
> TEE ごとに用意する。`ca-init` は **TEE 非依存**（P-384 鍵生成 + 自己署名のみ）
> なので内容は全 TEE 共通——当面 `sgx/` に置き、他 TEE では同スクリプトを流用する。

---

## SEV-SNP — `snp/bench_snp.sh`

事前に SNP CVM から bundle (`report.bin` / `certs/{ark,ask,vcek}.pem` /
`snp_endorsement.crt` / `ca.crt`) を `~/snp_verify_bundle` に用意し、`snpguest` を
ビルドしておく。

```bash
./snp/bench_snp.sh
RUNS=200 WARMUP=20 BUNDLE_DIR=/path/to/bundle ./snp/bench_snp.sh
```

計測: `A. snpguest verify certs` / `B. snpguest verify attestation` /
`C. tee-anchor verify (snp)`。tee-anchor は内部で snpguest を起動する**入れ子**構造
なので、**TEE Anchor 固有オーバーヘッド ≈ C − (A+B)** と解釈できる。

---

## Arm CCA — `cca/bench_cca.sh`

1. CCA マシン (Realm) から `cca-token.cbor` を `~/cca_verify_bundle` に持参。
2. evcli 用の CPAK 公開鍵を生成:
   ```bash
   python3 cca/gen_cpak_key.py             # ~/cca_verify_bundle/cpak.jwk, cpak.pem
   ```
3. 組織 endorsement を発行:
   ```bash
   tee-anchor ca-init   --out-dir ~/cca_verify_bundle
   tee-anchor provision --tee-type cca --token ~/cca_verify_bundle/cca-token.cbor \
       --ca-key ~/cca_verify_bundle/ca.key --ca-cert ~/cca_verify_bundle/ca.crt \
       --out ~/cca_verify_bundle/cca_endorsement.crt
   ```
4. 計測:
   ```bash
   ./cca/bench_cca.sh
   ```

**重要 (解釈)**: CCA では tee-anchor は evcli を呼ばず COSE/ES384 検証を自前実装する
独立実装。よって `B − A` は固有オーバーヘッドではなく、**evcli(Go) と tee-anchor(C++)
の総実行時間比較**であり、Go ランタイム起動コストが交絡する。論文ではその旨を明記。

> evcli は `ccatoken v1.4.0` 以降でないとトークンの新プロファイル
> `tag:arm.com,2023:cca_platform#1.0.0` を拒否する。素の `go install evcli@latest`
> (v0.0.2) は不可。ccatoken v1.4.0 で再ビルドした evcli を使うこと。

---

## Intel TDX — `tdx/rp_client.py`

これは [Humane-RAFW-TDX](https://github.com/) の `relying-party/rp_client.py` に
ベンチマークを統合した版（MIT, © Acompany Co., Ltd.）。**単体では動かない**:
`qvl_wrapper.py` / `libqvlwrapper.so` / `settings.toml` / `reference.toml` / 稼働中の
attester が必要なので、Humane-RAFW-TDX の `relying-party/` に戻して実行する。

`do_RA` は通常どおり 1 回 RA で信頼判定したあと、`BENCH=1` のときだけ `run_benchmark()`
を実行する。Quote は do_RA 冒頭で 1 回取得して使い回し、検証段のみループ計測する:

- **A**: 従来 RA = `verify_quote` (DCAP QVL) + `appraise_quote`
- **B**: A + `subprocess` で `tee-anchor verify --tee-type tdx`
- **Δ = B − A**: TEE Anchor を後付けした追加コスト（subprocess 起動込み）

```bash
# Humane-RAFW-TDX/relying-party/ にこの rp_client.py を置いた状態で
BENCH=1 BENCH_RUNS=50 BENCH_WARMUP=5 \
  ORG_CERT=./tdx_endorsement.crt ORG_CA=./ca.crt \
  TEE_ANCHOR=/path/to/tee-anchor \
  ./venv/bin/python3 rp_client.py
```

環境変数: `BENCH`(=1で有効) `BENCH_RUNS` `BENCH_WARMUP` `BENCH_OUT`(既定 ./bench_tdx.json)
`QUOTE_OUT` `TEE_ANCHOR` `ORG_CERT` `ORG_CA`。

**注意 (解釈)**: SNP のような入れ子ではなく、同一 Quote に対する従来 RA とは独立に
tee-anchor を足す**加算オーバーヘッド**。tee-anchor の TDX verify は PCK チェーンを
Quote 内蔵証明書でオフライン検証するため、Δ に追加のネットワーク往復は含まれない。

---

## Intel SGX (MAA) — `sgx/client_app.cpp`

これは [Humane-RAFW-MAA](https://github.com/acompany-develop/Humane-RAFW-MAA) の
`Client_App/client_app.cpp` に A/B 計測を統合した版（© Acompany Co., Ltd.）。**単体では
ビルド・実行できない**: SGX SDK・OpenSSL・`common/` ユーティリティ・稼働中の SGX サーバ
（attester）・Azure MAA への到達性が必要なので、Humane-RAFW-MAA の `Client_App/` に
**この `client_app.cpp` で元ファイルを置き換えて** `make` し直してから実行する。

`do_RA` は通常どおり 1 回 RA で信頼判定したあと、`BENCH=1` のときだけ `run_benchmark()`
を実行する。MAA は毎回ネットワーク往復を伴う（Quote 検証も JWK 取得も MAA への問い合わせ）
ため、TDX の「Quote 1 回取得 → 検証段のみ反復」とは異なり、**1 回取得した Quote を使い回し
つつ MAA への再送信を含む従来 RA をループ**する。問い合わせコストが高いのでループ回数は
ウォームアップ込みで 20 回程度に抑える:

- **A**: 従来 RA = `send_quote_to_maa`（MAA で Quote 検証）+ `process_ra_report`（JWK 取得・JWT 署名検証・Enclave 同一性検証）
- **B**: A + `system()` で `tee-anchor verify --tee-type sgx`
- **Δ = B − A**: TEE Anchor を後付けした追加コスト（subprocess 起動込み）

```bash
# Humane-RAFW-MAA/Client_App/client_app.cpp を本ファイルで置換し make 後、
# Client_App/ (settings_client.ini のあるディレクトリ) で:
BENCH=1 BENCH_RUNS=15 BENCH_WARMUP=5 \
  ORG_CERT=./sgx_endorsement.crt ORG_CA=./ca.crt \
  TEE_ANCHOR=/path/to/tee-anchor \
  ./client_app
```

環境変数: `BENCH`(=1で有効) `BENCH_RUNS`(既定 15) `BENCH_WARMUP`(既定 5)
`BENCH_OUT`(既定 ./bench_sgx.json) `QUOTE_OUT`(既定 ./quote.dat) `TEE_ANCHOR`
`ORG_CERT`(既定 ./sgx_endorsement.crt) `ORG_CA`(既定 ./ca.crt)。
`ORG_CERT` は `tee-anchor provision --tee-type sgx --pck-cert ... ` 等で事前発行しておく。

**注意 (解釈)**: TDX 同様の**加算オーバーヘッド**だが、ベースライン A が MAA への
ネットワーク往復を含むリモート検証である点が TDX (ローカル DCAP QVL) と異なる。よって
Δ（tee-anchor の SGX verify、Quote 内蔵 PCK チェーンをオフライン検証）と A の比較は、
**ローカル検証 vs リモート検証という構造差も交絡する**。論文ではその旨を明記する。

---

## 発行側コマンドの計測 (`ca-init` / `provision`)

`verify`（検証側）に加え、組織 PKI の**発行側**コスト（CA 構築 + マシンごとの
endorsement 発行）も計測する。いずれも単発の CLI コマンドなので
**hyperfine による A/B 計測**を基本とし、未インストール環境では各スクリプトが
**bash 簡易ループ計測にフォールバック**する（`date +%s%N` ベース。要 `gawk`）。

### `ca-init` — `sgx/bench_ca_init.sh`

`tee-anchor ca-init`（組織 Root CA 鍵生成 + 自己署名証明書）。**TEE 非依存**。
曲線ごと（P-256 / P-384=既定 / P-521）に独立コマンドとして測り、鍵生成コストの
差を見る。

```bash
./sgx/bench_ca_init.sh
RUNS=200 WARMUP=20 ./sgx/bench_ca_init.sh
```

**既存ファイルの影響排除**: `--force` で上書き計測すると本来の「空ディレクトリへの
新規発行」とコードパスが異なり得るうえ既存ファイル状態が計測を歪める。そこで
**各試行の直前（計測区間の外）で `ca.key`/`ca.crt` を削除**し、毎回まっさらな状態
からの新規発行を測る（hyperfine は `--prepare`、bash は反復前の `rm -f`、`--force`
は付けない）。

### `provision` — `sgx/bench_provision.sh`

`tee-anchor provision --tee-type sgx`（Quote パース → PCK チェーン抽出 → Chip ID
抽出 → CA 鍵で endorsement 証明書を署名・書出）。ネットワーク往復なし。署名用 CA は
スクリプト先頭で 1 度だけ `ca-init` して用意（**CA 生成コストは計測に含めない**）。
入力 Quote は `QUOTE=` で指定（未指定時は `Humane-RAFW-MAA(-rev)/quote.dat` 等を探索）。

```bash
QUOTE=/path/to/quote.dat ./sgx/bench_provision.sh
RUNS=200 WARMUP=20 ./sgx/bench_provision.sh
```

`provision` も毎回 `--out` の endorsement 証明書を書き出すため、`ca-init` と同様
**各試行の直前で `--out` を削除**してから測る。スクリプトは計測前に
`provision → verify` を 1 度実行して Chip ID 照合の成否（sanity）も表示する。

> **環境メモ**: 現状この開発機には `hyperfine` 未導入のため、両スクリプトは bash
> フォールバックで動作確認済み（参考値: P-256≈4.8ms / P-384≈6.5ms / P-521≈5.1ms、
> provision(sgx)≈6.8ms。OpenSSL は P-384 に専用アセンブリが無く P-521 より遅い）。
> 厳密計測には `sudo apt-get install hyperfine` を推奨。

---

## コミットしないもの

秘密・環境依存・再生成可能な成果物はリポジトリに含めない:

- 秘密鍵 `ca.key`、PCCS の Intel API キー等
- 証拠/入力: `quote.dat` / `report.bin` / `cca-token.cbor`、各 `*_endorsement.crt`、`ca.crt`
- 生成鍵 `cpak.jwk` / `cpak.pem`（`gen_cpak_key.py` で再生成）
- 環境依存設定 `settings.toml` / `reference.toml`
- 計測結果 `bench_*.json` / `bench_*.md`（必要なら別途 `results/` に）
- `venv/` / `*.so` / `__pycache__/`

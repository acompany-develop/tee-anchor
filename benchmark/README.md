# TEE Anchor ベンチマーク
**論文におけるTEE Anchor性能評価に使用したコード群を格納するフォルダ。前提とするパスの整理等が出来ておらず、一部では[Humane-RAFW-MAA](https://github.com/acompany-develop/Humane-RAFW-MAA)や[Humane-RAFW-TDX](https://github.com/acompany-develop/Humane-RAFW-TDX/tree/main)への組み込みを前提とする状況となっている。かつ以下の説明は全てClaudeに記述させたものである。あくまでも本ドキュメント及び各種ベンチマークのコードは参考用として見なしていただきたい。**

SGX / TDX / SEV-SNP / Arm CCA 横断の TEE Anchor について、コマンド別にコストを計測する
スクリプト集。主目的は **「従来 RA 検証器」と「TEE Anchor 検証（組織 endorsement chain
+ Chip ID 照合）」のコスト差**の測定だが、発行側コマンド（`ca-init` / `provision` /
`revoke`+`crl-issue`）の単発コストも併せて測れる。

## 検証側 (`verify`) の比較対象

| TEE | 従来 RA ベースライン | TEE Anchor | 計測手段 | スクリプト |
|-----|---------------------|-----------|----------|-----------|
| SEV-SNP | `snpguest verify` | `tee-anchor verify --tee-type snp` | `hyperfine` A/B | `snp/verify/bench_snp.sh` |
| Arm CCA | `evcli cca check` | `tee-anchor verify --tee-type cca` | `hyperfine` A/B | `cca/verify/bench_cca.sh` |
| Intel TDX | DCAP QVL (`verify_quote` + appraise) | `tee-anchor verify --tee-type tdx` | in-process ループ計測 | `tdx/verify/rp_client.py` |
| Intel SGX (MAA) | MAA への Quote 送信 + JWT/Enclave 検証 | `tee-anchor verify --tee-type sgx` | in-process ループ計測 | `sgx/verify/client_app.cpp` |

## 発行側コマンドの計測

| コマンド | 対象 | TEE 依存 | スクリプト |
|---------|------|---------|-----------|
| `provision` (sgx/tdx/cca/snp) | 証拠 → endorsement 証明書発行 | あり | `<tee>/provision/bench_provision.sh` |
| `ca-init` | 組織 Root CA 鍵 + 自己署名証明書 | なし | `ca-init/bench_ca_init.sh` |
| `revoke` + `crl-issue` | 失効 DB 追記 → CRL 署名発行（1 セット） | なし | `revoke-crl/bench_revoke_crl.sh` |

---

## 構成

```
benchmark/
├── README.md
├── snp/
│   ├── verify/bench_snp.sh           SNP verify: snpguest(従来) vs tee-anchor(自前) (hyperfine A/B/C)
│   └── provision/bench_provision.sh  SNP provision: report+certs → endorsement 発行
├── cca/
│   ├── verify/bench_cca.sh           CCA verify: evcli vs tee-anchor (hyperfine A/B)
│   ├── verify/gen_cpak_key.py        CCA: pin 済み CPAK → cpak.jwk/pem を生成 (evcli 入力用)
│   └── provision/bench_provision.sh  CCA provision: token → endorsement 発行
├── tdx/
│   ├── verify/rp_client.py           TDX verify: Humane-RAFW-TDX の RP に A/B 計測を統合 (MIT, Acompany)
│   └── provision/bench_provision.sh  TDX provision: Quote → endorsement 発行
├── sgx/
│   ├── verify/client_app.cpp         SGX(MAA) verify: Humane-RAFW-MAA の Client_App に A/B/C 計測を統合 (Acompany)
│   └── provision/bench_provision.sh  SGX provision: Quote → endorsement 発行
├── ca-init/bench_ca_init.sh          ca-init 計測 (TEE 非依存。曲線 P-256/384/521 比較)
└── revoke-crl/bench_revoke_crl.sh    revoke + crl-issue を 1 セットで計測 (TEE 非依存)
```

> **コマンド単位で分割**: TEE 依存コマンド（`verify` / `provision`）は TEE フォルダ配下に
> `verify/` `provision/` のサブフォルダを切る。TEE 非依存コマンド（`ca-init`,
> `revoke`+`crl-issue`）は専用フォルダに置く。

---

## 共通事項

### `tee-anchor` バイナリの探索

各スクリプトはリポジトリ直下でビルドした `tee-anchor` を呼ぶ。`TEE_ANCHOR=<path>` で
明示指定でき、未指定時は「スクリプトからの相対パス（リポジトリ直下）」→
`~/Develop/tee-anchor/tee-anchor` → PATH 上の `tee-anchor` の順に探索する。

```bash
# リポジトリ直下でビルド
make            # → ./tee-anchor
```

### 計測ツール（hyperfine / bash フォールバック）

単発 CLI を測る `provision` / `ca-init` / `revoke-crl` と `snp/verify` は **hyperfine** を
使う。`provision` / `ca-init` / `revoke-crl` は hyperfine 未導入環境では **bash 簡易ループ
計測に自動フォールバック**する（`date +%s%N` ベース。要 `gawk`）。`snp/verify/bench_snp.sh`
は hyperfine 必須。

```bash
sudo apt-get install hyperfine     # 推奨（より厳密な統計）
```

### 反復回数の既定

| スクリプト | WARMUP | RUNS | 環境変数 |
|-----------|--------|------|---------|
| `*/provision/bench_provision.sh` | 20 | 200 | `WARMUP` / `RUNS` |
| `ca-init/bench_ca_init.sh` | 20 | 200 | `WARMUP` / `RUNS` |
| `revoke-crl/bench_revoke_crl.sh` | 20 | 200 | `WARMUP` / `RUNS` |
| `snp/verify/bench_snp.sh` | 5 | 50 | `WARMUP` / `RUNS` |
| `tdx/verify/rp_client.py` | 5 | 50 | `BENCH_WARMUP` / `BENCH_RUNS` |
| `sgx/verify/client_app.cpp` | 5 | 15 | `BENCH_WARMUP` / `BENCH_RUNS` |

> MAA（SGX）はネットワーク往復を含むため反復は少なめ。TEE 横断で `provision` を公正に
> 比較できるよう、4 つの provision はすべて同条件（warmup=20 / runs=200）に揃えてある。

---

## 検証側 — `verify`

### SEV-SNP — `snp/verify/bench_snp.sh`

事前に SNP CVM から bundle（`report.bin` / `certs/{ark,ask,vcek}.pem` /
`snp_endorsement.crt` / `ca.crt`）を `~/snp_verify_bundle` に用意し、`snpguest` を
ビルドしておく（証拠の生成手順は下記「SNP 入力の生成」を参照）。

```bash
./snp/verify/bench_snp.sh
RUNS=200 WARMUP=20 BUNDLE_DIR=/path/to/bundle ./snp/verify/bench_snp.sh
```

計測: `A. snpguest verify certs` / `B. snpguest verify attestation` /
`C. tee-anchor verify (snp)`。A/B は**従来手法**（ベンダーツール snpguest を 2 回 fork/exec）の
ベンダー検証、C は tee-anchor が同等のベンダー検証（ARK pin + チェーン + Report 署名）を
OpenSSL で**インプロセス**実行し、さらに組織 endorsement chain + Chip ID 照合まで 1 プロセスで
行う（snpguest は一切起動しない）。**従来方式 (A+B を別プロセス) に対するサブプロセス削減の効果は
概ね (A+B) と C の差**として読める。

### Arm CCA — `cca/verify/bench_cca.sh`

1. CCA マシン（Realm）から `cca-token.cbor` を `~/cca_verify_bundle` に持参。
2. evcli 用の CPAK 公開鍵を生成:
   ```bash
   python3 cca/verify/gen_cpak_key.py      # ~/cca_verify_bundle/cpak.jwk, cpak.pem
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
   ./cca/verify/bench_cca.sh
   ```

**重要 (解釈)**: CCA では tee-anchor は evcli を呼ばず COSE/ES384 検証を自前実装する
独立実装。よって `B − A` は固有オーバーヘッドではなく、**evcli(Go) と tee-anchor(C++)
の総実行時間比較**であり、Go ランタイム起動コストが交絡する。論文ではその旨を明記。

> evcli は `ccatoken v1.4.0` 以降でないとトークンの新プロファイル
> `tag:arm.com,2023:cca_platform#1.0.0` を拒否する。素の `go install evcli@latest`
> (v0.0.2) は不可。ccatoken v1.4.0 で再ビルドした evcli を使うこと。

### Intel TDX — `tdx/verify/rp_client.py`

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

### Intel SGX (MAA) — `sgx/verify/client_app.cpp`

これは [Humane-RAFW-MAA](https://github.com/acompany-develop/Humane-RAFW-MAA) の
`Client_App/client_app.cpp` に A/B/C 計測を統合した版（© Acompany Co., Ltd.）。**単体では
ビルド・実行できない**: SGX SDK・OpenSSL・`common/` ユーティリティ・稼働中の SGX サーバ
（attester）・Azure MAA への到達性が必要なので、Humane-RAFW-MAA の `Client_App/` に
**この `client_app.cpp` で元ファイルを置き換えて** `make` し直してから実行する。

`do_RA` は通常どおり 1 回 RA で信頼判定したあと、`BENCH=1` のときだけ `run_benchmark()`
を実行する。MAA は毎回ネットワーク往復を伴う（Quote 検証も JWK 取得も MAA への問い合わせ）
ため、TDX の「Quote 1 回取得 → 検証段のみ反復」とは異なり、**1 回取得した Quote を使い回し
つつ MAA への再送信を含む従来 RA をループ**する。問い合わせコストが高いのでループ回数は
ウォームアップ込みで 20 回程度に抑える:

- **A**: 従来 RA = `send_quote_to_maa`（MAA で Quote 検証）+ `process_ra_report`（JWK 取得・JWT 署名検証・Enclave 同一性検証）
- **B**: A + `system()` で `tee-anchor verify --tee-type sgx`（CRL なし）
- **C**: A + `system()` で `tee-anchor verify --tee-type sgx --crl <ORG_CRL>`（**`ORG_CRL` 指定時のみ**）
- **Δ = B − A**: TEE Anchor を後付けした追加コスト（subprocess 起動込み）
- **Δ' = C − A** / **CRL 純増 = C − B**: 失効リストを渡した場合の追加コスト

```bash
# Humane-RAFW-MAA/Client_App/client_app.cpp を本ファイルで置換し make 後、
# Client_App/ (settings_client.ini のあるディレクトリ) で:
BENCH=1 BENCH_RUNS=15 BENCH_WARMUP=5 \
  ORG_CERT=./sgx_endorsement.crt ORG_CA=./ca.crt \
  ORG_CRL=./crl.pem \                  # ← 指定すると CRL シナリオ(C)も計測
  TEE_ANCHOR=/path/to/tee-anchor \
  ./client_app
```

環境変数: `BENCH`(=1で有効) `BENCH_RUNS`(既定 15) `BENCH_WARMUP`(既定 5)
`BENCH_OUT`(既定 ./bench_sgx.json) `QUOTE_OUT`(既定 ./quote.dat) `TEE_ANCHOR`
`ORG_CERT`(既定 ./sgx_endorsement.crt) `ORG_CA`(既定 ./ca.crt) `ORG_CRL`(任意; 未指定なら C スキップ)。
`ORG_CERT` は `tee-anchor provision --tee-type sgx --quote ... ` で、`ORG_CRL` は
`tee-anchor crl-issue ...` で事前発行しておく（対象が未失効なら C は exit 0、失効済みなら exit 24）。

**注意 (解釈)**: TDX 同様の**加算オーバーヘッド**だが、ベースライン A が MAA への
ネットワーク往復を含むリモート検証である点が TDX (ローカル DCAP QVL) と異なる。よって
Δ（tee-anchor の SGX verify、Quote 内蔵 PCK チェーンをオフライン検証）と A の比較は、
**ローカル検証 vs リモート検証という構造差も交絡する**。論文ではその旨を明記する。

> **参考値 (この開発機, warmup=5 runs=15, ORG_CRL=4 件の CRL)**:
> A≈117.3ms / B≈123.1ms (Δ≈**5.72ms**, 従来 RA の 4.9%) / C≈123.6ms。
> **CRL 純増 (C−B)≈0.52ms**（CRL ロード + CA による CRL 署名検証 + leaf 失効照合）。
> A の絶対値・分散は MAA ネットワークレイテンシ依存で変動する点に留意。

---

## 発行側 — `provision`（sgx / tdx / cca / snp）

`<tee>/provision/bench_provision.sh` は `tee-anchor provision --tee-type <tee>`
（証拠のパース・ベンダー検証 → Chip ID 抽出 → CA 鍵で組織 endorsement 証明書を署名・書出）
の単発コストを計測する。4 つとも同じ流儀:

- 署名用 CA（ca.key/ca.crt）は**スクリプト先頭で 1 度だけ** `ca-init` して用意する
  （**CA 生成コストは計測に含めない**）。
- `provision` は毎回 `--out` の endorsement 証明書を書き出すため、**各試行の直前
  （計測区間の外）で `--out` を削除**してから測る（hyperfine は `--prepare`、bash
  フォールバックは反復前の `rm -f`）。毎回まっさらな新規発行を測るのが狙い。
- 計測前に `provision → verify` を 1 度実行し、**発行した endorsement が Chip ID 照合に
  成功するか（sanity）**を表示する。
- 既定は **warmup=20 / runs=200**。`WARMUP` / `RUNS` / `TEE_ANCHOR` / `CA_CURVE`(既定 P-384) /
  `OUT_PREFIX`(既定 bench_provision) で上書き可。結果は `bench_provision.{md,json}`。

TEE ごとに異なるのは **入力（証拠）と内部のベンダー検証手段**のみ:

| TEE | 入力フラグ | 入力の既定探索 | 内部のベンダー検証 |
|-----|-----------|---------------|-------------------|
| SGX | `--quote <file>` | `QUOTE=` / `Humane-RAFW-MAA(-rev)/quote.dat` | Quote 内蔵 PCK チェーンをインプロセス検証 |
| TDX | `--quote <file>` | `QUOTE=` / `Humane-RAFW-TDX/.../quote.dat` | TD Quote(v4/v5) 内蔵 PCK チェーンをインプロセス検証 |
| CCA | `--token <file>` | `TOKEN=` / `~/cca_verify_bundle/cca-token.cbor` | pin 済み CPAK で COSE/ES384 をインプロセス検証 |
| SNP | `--report <file>` `--certs <dir>` | `BUNDLE_DIR=` (既定 `~/snp_verify_bundle`) の `report.bin` / `certs/` | ARK pin 照合 + ARK→ASK→VCEK チェーン + Report 署名を**インプロセス**検証 |

```bash
# SGX
QUOTE=/path/to/quote.dat ./sgx/provision/bench_provision.sh
# TDX
QUOTE=/path/to/td_quote.dat ./tdx/provision/bench_provision.sh
# CCA
TOKEN=/path/to/cca-token.cbor ./cca/provision/bench_provision.sh
# SNP（BUNDLE_DIR から report.bin / certs/ を拾う）
./snp/provision/bench_provision.sh
RUNS=200 WARMUP=20 BUNDLE_DIR=/path/to/bundle ./snp/provision/bench_provision.sh
```

> **TEE 横断比較の注意 (解釈)**: SGX/TDX は Quote 内蔵 PCK チェーンを、CCA は pin 済み
> CPAK を、SNP は ARK pin + VCEK チェーン + Report 署名を、**いずれもインプロセス**で
> 検証する（旧版では SNP のみ snpguest を 2 回 fork/exec していたが、自前実装に置き換えた
> ため、この非対称性は解消された）。4 者は同条件で並べられる。

### SNP 入力の生成

SNP の `verify` / `provision` ベンチはどちらも `~/snp_verify_bundle/{report.bin, certs/}`
を入力に取る（「既に存在する前提」で生成はしない）。これらは SEV-SNP CVM 上で snpguest を
使って生成する。サンプル手順は `provision/sev-snp/snp_sample/get_attestation.sh`
（リポジトリ直下の `provision/` 配下）にある。要点:

```bash
SNPGUEST=~/snpguest/target/release/snpguest
cd ~/snp_verify_bundle
sudo "$SNPGUEST" report report.bin request-data.txt --random   # /dev/sev-guest ioctl は要 sudo
sudo chown "$(id -u):$(id -g)" report.bin request-data.txt
"$SNPGUEST" fetch ca pem  certs --report report.bin            # ark.pem / ask.pem
"$SNPGUEST" fetch vcek pem certs report.bin                    # vcek.pem
"$SNPGUEST" verify certs       certs                           # sanity
"$SNPGUEST" verify attestation certs report.bin               # sanity
```

`verify` ベンチではさらに `snp_endorsement.crt` と `ca.crt` を bundle に置く必要がある
（`ca-init` + `provision --tee-type snp` で発行）。

---

## 発行側 — `ca-init` / `revoke`+`crl-issue`（TEE 非依存）

### `ca-init` — `ca-init/bench_ca_init.sh`

`tee-anchor ca-init`（組織 Root CA 鍵生成 + 自己署名証明書）。**TEE 非依存**。
曲線ごと（P-256 / P-384=既定 / P-521）に独立コマンドとして測り、鍵生成コストの
差を見る。

```bash
./ca-init/bench_ca_init.sh
RUNS=200 WARMUP=20 ./ca-init/bench_ca_init.sh
```

**既存ファイルの影響排除**: `--force` で上書き計測すると本来の「空ディレクトリへの
新規発行」とコードパスが異なり得るうえ既存ファイル状態が計測を歪める。そこで
**各試行の直前（計測区間の外）で `ca.key`/`ca.crt` を削除**し、毎回まっさらな状態
からの新規発行を測る（hyperfine は `--prepare`、bash は反復前の `rm -f`、`--force`
は付けない）。

### `revoke` + `crl-issue` — `revoke-crl/bench_revoke_crl.sh`

証明書ライフサイクルの**失効系**を、`revoke`（失効 DB へ追記）→ `crl-issue`
（DB から CRL を署名・発行）の **1 セット**として計測する（個別ではなくセット）。
revoke/crl-issue も **TEE 非依存**の純 PKI 操作。署名用 CA と失効対象 endorsement は
先頭で 1 度だけ用意する（その生成コストは計測に含めない。endorsement 発行に `QUOTE=`
を使用）。

```bash
./revoke-crl/bench_revoke_crl.sh                    # 既定 WARMUP=20 RUNS=200
QUOTE=/path/to/quote.dat ./revoke-crl/bench_revoke_crl.sh
RUNS=200 WARMUP=20 ./revoke-crl/bench_revoke_crl.sh
```

**既存状態の影響排除**: `crl-issue` のコストは失効 DB のエントリ数に依存する。同じ
DB に revoke を積み増すと DB が単調増加し計測が歪むため、**各試行の直前（計測区間
の外）で失効 DB と CRL 出力を削除**し、毎回「空 DB → 1 件 revoke → 1 件 CRL 発行」
という同一条件のセットコストを測る（hyperfine は `--prepare`、bash は反復前 `rm -f`）。
hyperfine では `revoke && crl-issue` を 1 コマンド列としてシェル経由で測る（`&&` の
ため `-N` は使わない）。

> **参考値 (この開発機, hyperfine, warmup=20 runs=200)**:
> revoke+crl-issue セット ≈ **7.07 ± 0.15 ms** (median 7.04 / min 6.88 / max 8.67)。
> ca-init は P-256≈4.8ms / P-384≈6.5ms / P-521≈5.1ms、provision(sgx)≈6.8ms。
> (OpenSSL は P-384 に専用アセンブリが無く P-521 より遅い。)
> `hyperfine` 未導入の環境では各スクリプトが bash 簡易計測へ自動フォールバックする。

---

## コミットしないもの

秘密・環境依存・再生成可能な成果物はリポジトリに含めない（`.gitignore` 済み）:

- 秘密鍵 `ca.key`、PCCS の Intel API キー等
- 証拠/入力: `quote.dat` / `report.bin` / `cca-token.cbor` / `certs/`、各 `*_endorsement.crt`、`ca.crt`
- 生成鍵 `cpak.jwk` / `cpak.pem`（`gen_cpak_key.py` で再生成）
- 環境依存設定 `settings.toml` / `reference.toml`
- 計測結果 `bench_*.json` / `bench_*.md`（必要なら別途 `results/` に）
- `venv/` / `*.so` / `__pycache__/`

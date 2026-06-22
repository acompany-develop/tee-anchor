# TEE Anchor ベンチマーク

SGX/TDX/SNP/CCA 横断の TEE Anchor について、**「従来 RA 検証器」と「TEE Anchor 検証
（組織 endorsement chain + Chip ID 照合）」のコスト差**を計測するためのスクリプト集。

| TEE | 従来 RA ベースライン | TEE Anchor | 計測手段 |
|-----|---------------------|-----------|----------|
| SEV-SNP | `snpguest verify` | `tee-anchor verify --tee-type snp` | `hyperfine` (`snp/bench_snp.sh`) |
| Arm CCA | `evcli cca check` | `tee-anchor verify --tee-type cca` | `hyperfine` (`cca/bench_cca.sh`) |
| Intel TDX | DCAP QVL (`verify_quote` + appraise) | `tee-anchor verify --tee-type tdx` | in-process ループ計測 (`tdx/rp_client.py`) |
| Intel SGX (MAA) | MAA への Quote 送信 + JWT/Enclave 検証 | `tee-anchor verify --tee-type sgx` | in-process ループ計測 (`sgx/verify/client_app.cpp`) |

> 各スクリプトは `tee-anchor` バイナリ（リポジトリ直下でビルドしたもの）を呼ぶ。
> `TEE_ANCHOR=<path>` で明示指定可。未指定時は `../../tee-anchor` と `~/Develop/tee-anchor/tee-anchor` を探索。

---

## 構成

```
benchmark/
├── README.md
├── snp/bench_snp.sh                 SNP verify: snpguest vs tee-anchor (hyperfine A/B)
├── cca/bench_cca.sh                 CCA verify: evcli vs tee-anchor (hyperfine A/B)
├── cca/gen_cpak_key.py              CCA: pin 済み CPAK → cpak.jwk/pem を生成 (evcli 入力用)
├── tdx/rp_client.py                 TDX verify: Humane-RAFW-TDX の RP に A/B 計測を統合 (MIT, Acompany)
├── sgx/verify/client_app.cpp        SGX(MAA) verify: Humane-RAFW-MAA の Client_App に A/B/(C) 計測を統合 (Acompany)
├── sgx/verify/bench_verify_crl.sh   SGX verify の CRL(失効リスト)有無による A/B/C 単体計測 (hyperfine)
├── sgx/provision/bench_provision.sh SGX provision 計測 (Quote→endorsement 発行)
├── ca-init/bench_ca_init.sh         ca-init 計測 (TEE 非依存。曲線 P-256/384/521 比較)
└── revoke-crl/bench_revoke_crl.sh   revoke + crl-issue を 1 セットで計測 (TEE 非依存)
```

> **コマンドごとの分割**: `verify` だけでなく `ca-init` / `provision` / `revoke`+`crl-issue`
> も計測対象。**コマンド単位**でフォルダ/スクリプトを分ける方針。TEE 依存コマンド
> (`verify`/`provision`) は TEE フォルダ配下 (`sgx/verify/`, `sgx/provision/` …)、
> TEE 非依存コマンド (`ca-init`, `revoke`+`crl-issue`) は専用フォルダ
> (`ca-init/`, `revoke-crl/`) に置く。
>
> **CRL(失効リスト)有無の verify コスト**は 2 通りで測れる:
> (1) `sgx/verify/bench_verify_crl.sh` — `tee-anchor verify` を hyperfine で単体 A/B/C 計測、
> (2) `sgx/verify/client_app.cpp` の `ORG_CRL` オプション — MAA RA パイプラインに統合し、
> tee-anchor verify を「CRL なし(B)/--crl 付き(C)」両方 subprocess 実行して in-process 計測。

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

## Intel SGX (MAA) — `sgx/verify/client_app.cpp`

これは [Humane-RAFW-MAA](https://github.com/acompany-develop/Humane-RAFW-MAA) の
`Client_App/client_app.cpp` に A/B(/C) 計測を統合した版（© Acompany Co., Ltd.）。**単体では
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

### verify の CRL 有無コスト（単体計測） — `sgx/verify/bench_verify_crl.sh`

`tee-anchor verify --tee-type sgx` に **失効リスト (CRL) が渡された場合**の追加コストを
A/B/C で計測する（`--crl` は組織 endorsement(leaf) に `X509_V_FLAG_CRL_CHECK` を有効化）。

- **A**: `verify`（CRL なし）→ 受理 (exit 0)
- **B**: `verify --crl`（対象は CRL に**未掲載** = 未失効）→ 受理 (exit 0)
- **C**: `verify --crl`（対象が CRL に**掲載** = 失効）→ 失効検出 (exit 24)

`Δ(B−A)` が「失効リストが渡された場合」の純オーバーヘッド（CRL の PEM ロード +
CA による CRL 署名検証 + leaf の失効照合）。支配項は CRL の ECDSA 署名検証で、
エントリ数 N への依存は小さい（B 用 CRL は現実性のため対象外証明書を `CRL_ENTRIES`
件=既定 4 失効させて作る）。C は `X509_V_ERR_CERT_REVOKED` でチェーン検証段が失敗し
Chip ID 照合の手前で停止する。CA・endorsement・2 種の CRL は計測前に 1 度だけ用意する
（生成コストは計測に含めない）。`verify` は読み取り専用のため試行ごとの掃除は不要。

```bash
./sgx/verify/bench_verify_crl.sh                            # 既定 WARMUP=20 RUNS=200
QUOTE=/path/to/quote.dat ./sgx/verify/bench_verify_crl.sh
CRL_ENTRIES=100 ./sgx/verify/bench_verify_crl.sh            # CRL の失効件数を増やす
```

> **参考値 (この開発機, hyperfine, warmup=20 runs=200)**:
> A≈**4.70ms** / B≈**5.50ms** / C≈**4.70ms**。
> よって **Δ(B−A)≈0.81ms (+17.2%)** が CRL 処理の純オーバーヘッド。C(失効)は
> 早期失敗のため A とほぼ同等。

---

## 発行側コマンドの計測 (`ca-init` / `provision`)

`verify`（検証側）に加え、組織 PKI の**発行側**コスト（CA 構築 + マシンごとの
endorsement 発行）も計測する。いずれも単発の CLI コマンドなので
**hyperfine による A/B 計測**を基本とし、未インストール環境では各スクリプトが
**bash 簡易ループ計測にフォールバック**する（`date +%s%N` ベース。要 `gawk`）。

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

### `provision` — `sgx/provision/bench_provision.sh`

`tee-anchor provision --tee-type sgx`（Quote パース → PCK チェーン抽出 → Chip ID
抽出 → CA 鍵で endorsement 証明書を署名・書出）。ネットワーク往復なし。署名用 CA は
スクリプト先頭で 1 度だけ `ca-init` して用意（**CA 生成コストは計測に含めない**）。
入力 Quote は `QUOTE=` で指定（未指定時は `Humane-RAFW-MAA(-rev)/quote.dat` 等を探索）。

```bash
QUOTE=/path/to/quote.dat ./sgx/provision/bench_provision.sh
RUNS=200 WARMUP=20 ./sgx/provision/bench_provision.sh
```

`provision` も毎回 `--out` の endorsement 証明書を書き出すため、`ca-init` と同様
**各試行の直前で `--out` を削除**してから測る。スクリプトは計測前に
`provision → verify` を 1 度実行して Chip ID 照合の成否（sanity）も表示する。

### `revoke` + `crl-issue` — `revoke-crl/bench_revoke_crl.sh`

証明書ライフサイクルの**失効系**を、`revoke`（失効 DB へ追記）→ `crl-issue`
（DB から CRL を署名・発行）の **1 セット**として計測する（個別ではなくセット）。
revoke/crl-issue も **TEE 非依存**の純 PKI 操作なので、TEE 別フォルダの外の
`revoke-crl/` に置く。署名用 CA と失効対象 endorsement は先頭で 1 度だけ用意する
（その生成コストは計測に含めない。endorsement 発行に `QUOTE=` を使用）。

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

> **参考値 (この開発機)**: `hyperfine` 利用可。warmup=20 runs=200 で
> revoke+crl-issue セット ≈ **7.07 ± 0.15 ms** (median 7.04 / min 6.88 / max 8.67)。
> ca-init は P-256≈4.8ms / P-384≈6.5ms / P-521≈5.1ms、provision(sgx)≈6.8ms。
> (OpenSSL は P-384 に専用アセンブリが無く P-521 より遅い。)
> `hyperfine` 未導入の環境では各スクリプトが bash 簡易計測へ自動フォールバックする。

---

## コミットしないもの

秘密・環境依存・再生成可能な成果物はリポジトリに含めない:

- 秘密鍵 `ca.key`、PCCS の Intel API キー等
- 証拠/入力: `quote.dat` / `report.bin` / `cca-token.cbor`、各 `*_endorsement.crt`、`ca.crt`
- 生成鍵 `cpak.jwk` / `cpak.pem`（`gen_cpak_key.py` で再生成）
- 環境依存設定 `settings.toml` / `reference.toml`
- 計測結果 `bench_*.json` / `bench_*.md`（必要なら別途 `results/` に）
- `venv/` / `*.so` / `__pycache__/`

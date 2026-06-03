# TEE Anchor

> **Cross-TEE Organizational Endorsement for Mitigating TEE Physical Attacks**

組織独自 PKI ベースの追加検証機構で、TEE（Intel SGX/TDX、AMD SEV-SNP 等）への物理攻撃 (Battering RAM, TEE.fail, BORE 等) を介した **Proxy / Relay 攻撃を間接的に防ぐ**スタンドアロン CLI ツール。Quote の PCK / VCEK 証明書に含まれる Chip ID（PPID 等）と、組織 CA が発行したエンドースメント証明書中の Chip ID を bit-for-bit 照合することで、物理侵害された手元マシンを使ったなりすましを検出します。

設計詳細・脅威モデル・既存研究との比較は `docs/` 配下を参照：

- `docs/design.md` — プロトコル設計、X.509 拡張 OID 設計、CRL 設計、exit code 表
- `docs/threat-model.md`
- `docs/related-work.md`

---

## 必要環境

- Ubuntu 24.04 (他の Linux でも動くはずですが動作確認は 24.04 のみ)
- `g++` 11+ または `clang++` 14+ (C++17 必須)
- **OpenSSL 3.x の開発ヘッダ・ライブラリ** (`libssl-dev` だけで十分。SGX SDK は本体には不要)

```sh
sudo apt-get install -y build-essential libssl-dev
```

> Phase 1 の現状スコープは **SGX のみ**。TDX / SEV-SNP は Phase 2 で順次追加予定。

---

## ビルド

```sh
make            # tee-anchor バイナリを生成
make clean      # 生成物を削除
```

成果物はルート直下の `./tee-anchor` のみ（単一バイナリ）。

---

## サブコマンド一覧

| サブコマンド | 役割 |
|---|---|
| `ca-init`   | 組織 Root CA 鍵 + 自己署名証明書を発行 |
| `provision` | Quote から PPID を抽出 → 組織 CA で署名した endorsement 証明書を発行 |
| `verify`    | Quote + endorsement + 組織 CA で Chip ID binding を検証 (任意で CRL チェック) |
| `revoke`    | endorsement の serial を失効リスト DB に追加 |
| `crl-issue` | DB から X.509 CRL を発行 |

各サブコマンドの詳細は `./tee-anchor <subcmd> --help`。

---

## クイックスタート (End-to-End)

`provision/sgx/sgx_sample/quote.dat` を入力として通しの流れを確認できます（実機でない場合は事前に SGX 実機で sgx_sample を実行して `quote.dat` を取得しておく必要があります。詳細は `provision/sgx/sgx_sample/README.md` を参照）。

```sh
W=/tmp/tea_demo
rm -rf "$W" && mkdir -p "$W"

# 1. 組織 CA を作る
./tee-anchor ca-init --out-dir "$W"

# 2. Quote から組織 endorsement 証明書を発行 (provision)
./tee-anchor provision \
    --quote   provision/sgx/sgx_sample/quote.dat \
    --ca-key  "$W/ca.key" \
    --ca-cert "$W/ca.crt" \
    --out     "$W/endorsement.crt"

# 3. 検証 (verify) — 成功すれば exit 0
./tee-anchor verify \
    --quote    provision/sgx/sgx_sample/quote.dat \
    --org-cert "$W/endorsement.crt" \
    --org-ca   "$W/ca.crt"
echo "exit=$?"
```

成功時の出力：

```
verify: OK
  tee_type       : sgx (0)
  chip_id (hex)  : 00112233445566778899aabbccddeeff
  ...
```

### 失効を試す (revoke → crl-issue → verify --crl)

```sh
# 失効リスト DB にエントリ追加 (まだ CRL ファイルは出ない)
./tee-anchor revoke \
    --ca-cert "$W/ca.crt" \
    --cert    "$W/endorsement.crt" \
    --reason  keyCompromise

# DB から CRL を発行
./tee-anchor crl-issue \
    --ca-key  "$W/ca.key" \
    --ca-cert "$W/ca.crt" \
    --out     "$W/crl.pem"

# CRL 付きで verify → 失効を検出して exit 24
./tee-anchor verify \
    --quote    provision/sgx/sgx_sample/quote.dat \
    --org-cert "$W/endorsement.crt" \
    --org-ca   "$W/ca.crt" \
    --crl      "$W/crl.pem"
echo "exit=$?"   # → 24
```

`--crl` は **任意指定**で、付けない verify は CRL チェックなしで動作します（後方互換）。

---

## verify の exit code

| code | 意味 |
|---:|---|
| 0  | 全検証成功 |
| 20 | PCK chain 検証失敗 (Quote が偽 or 改竄、Intel Root に紐付かない) |
| 21 | 組織 endorsement chain 検証失敗 (CA 不一致など) |
| 22 | **Chip ID 不一致 (= Proxy/Relay 攻撃検出)** |
| 24 | 組織 CRL により endorsement が失効済み |
| 30 | I/O / 内部エラー |

詳細は `docs/design.md` の Exit Code 設計を参照。

---

## SGX Quote の取得

TEE Anchor 本体は SGX SDK に依存しませんが、入力に渡す `quote.dat` は実機の SGX で生成する必要があります。Quote 取得用の最小サンプル（環境構築自動化込み）を以下に同梱しています：

- `provision/sgx/sgx_sample/` — DCAP ベースで `sgx_qe_get_quote` を 1 回呼んで `quote.dat` を吐くだけのミニサンプル
- `provision/sgx/sgx_sample/README.md` — 詳細な導入手順とビルド方法

```sh
# (実機 SGX マシン上で)
cd provision/sgx/sgx_sample
make setup        # SGX SDK / DCAP ランタイム / qcnl を一括導入 (Ubuntu 24.04 / Intel APT)
source /opt/intel/sgxsdk/environment
make run          # quote.dat を生成
```

---

## ディレクトリ構成

```
tee-anchor/
├── tee_anchor.cpp              main: サブコマンド dispatch
├── Makefile
├── common/                     共有ヘッダ (RAII, 例外, I/O, PKI ユーティリティ)
├── ca/                         ca-init / revoke / crl-issue
├── binding/                    ChipIdBinding 拡張の DER エンコード/デコード
├── provision/                  provision サブコマンド (+ SGX 固有処理)
│   └── sgx/
│       ├── sgx_provision.{hpp,cpp}      Quote パース + PCK chain 検証 + PPID 抽出
│       ├── intel_sgx_root_pubkey.hpp    Intel SGX Root CA 公開鍵 (QvE と同値)
│       └── sgx_sample/                  Quote 取得用ミニサンプル
├── verify/                     verify サブコマンド
└── docs/                       設計ドキュメント
```

---

## ライセンス・連絡先

学会投稿 (国内 CSS) を目的とした PoC 実装です。production-quality のセキュリティ保証は付きません。

詳細は `CLAUDE.md` 内の連絡事項セクションを参照。

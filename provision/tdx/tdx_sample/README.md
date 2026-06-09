# TDX 最小 TD Quote 取得サンプル

TEE Anchor の `provision` / `verify`（TDX 経路）に渡す **`quote.dat` を実機 TDX 上で 1 個生成するだけ**の最小サンプル。
Humane-RAFW-TDX の `attester/tdx_wrapper.c` の Quote 生成部分から、Python FFI・HTTP・鍵交換を全て剥がしてスタンドアロン CLI にしてある。

> このサンプルは TEE Anchor 本体（Endorser/Verifier）の一部ではなく、**評価用に Attester 側の入力を作るためのハーネス**です。本体は生成済み `quote.dat` をファイル入力として消費するだけです。

## SGX サンプルとの違い

TDX は SGX と違い、Enclave も署名（edger8r / sgx_sign）も不要です。ゲスト（TD）内の `libtdx_attest` が以下を内部で隠蔽します:

```
tdx_att_get_quote()
  → TDREPORT 生成 (/dev/tdx_guest ioctl)
    → vsock 経由でホストの QGS (Quote Generation Service) に転送
      → TD Quoting Enclave が Quote を生成
```

呼び出し側は `report_data` を渡して Quote を受け取るだけです。GCP/Azure などの Confidential VM では QGS は**ホスト側**にあるため、ゲストに QGS を立てる必要はありません。

## 構成

```
tdx_sample/
├── get_quote.c     # tdx_att_get_quote → quote.dat（version/tee_type を表示）
├── Makefile        # gcc -ltdx_attest（all/run/setup/check-env/clean）
├── setup.sh        # 環境構築の自動化（Intel APT リポジトリ + libtdx-attest 等）
└── README.md
```

## 前提（実機側）

- Intel TDX ゲスト（TD）上で実行すること。`/dev/tdx_guest` が存在すること。
- 本サンプルは **Ubuntu 24.04 / GCP Confidential VM (TDX)** を想定。
- 環境構築は `setup.sh` で自動化済み（手動導入も可）。

## 環境構築

Intel 公式 APT リポジトリから TDX attest ランタイム・開発ヘッダ・QPL を導入する。**sudo が必要**。

`make` 自体が未導入のクリーン環境では、まず `setup.sh` を直接実行する（スクリプト内で `build-essential` = `make` 含む を導入するため、ブートストラップを兼ねる）：

```sh
sudo ./setup.sh
```

`make` 導入済みなら Makefile 経由でもよい：

```sh
sudo make setup     # = sudo ./setup.sh （一括構築）
make check-env      # = ./setup.sh --check （構築せず診断のみ）
```

導入されるパッケージ:

| パッケージ | 役割 |
|---|---|
| `libtdx-attest` | `tdx_att_get_quote()` 本体（`libtdx_attest.so`） |
| `libtdx-attest-dev` | `tdx_attest.h`（ビルドに必要） |
| `libsgx-dcap-default-qpl` | コラテラル取得（QPL）。導入時に `/etc/sgx_default_qcnl.conf` の既定が自動配置される |
| `libsgx-dcap-ql` | DCAP Quoting ライブラリ（依存補完） |

> **QCNL 設定について**: `/etc/sgx_default_qcnl.conf` は `libsgx-dcap-default-qpl` 導入時に既定ファイル（Intel PCS 直フェッチ）が自動配置されるため、本サンプルでは独自 conf を同梱・上書きしません。SGX サンプルが Azure THIM 用 conf を同梱していたのと対照的に、TDX では Azure 固有のカスタマイズは不要です。なお Quote の**生成**自体はホスト側 QGS が PCK 証明書を埋め込むため、この conf が効くのは主に**検証**時（TCB / QE Identity / CRL のコラテラル取得）です。自前 PCCS を使う場合のみ手動で編集してください。

## ビルドと実行

```sh
make                       # get_quote をビルド
./get_quote                # quote.dat を生成（既定の出力名）
# または
./get_quote my_quote.dat "hello"   # 出力名と report_data(最大64B) を指定
make run                   # ビルド込みで一括実行
```

> `/dev/tdx_guest` へのアクセスに root が要る環境が多い。`Permission denied` の場合は `sudo ./get_quote` で実行すること。

成功すると以下が表示される：

```
TD Quote written: quote.dat (NNNN bytes)
  quote version : 4
  att key type  : 2 (ECDSA-P256)
  tee type      : 0x00000081 (TDX: OK)
```

`quote version = 4` / `tee type = 0x00000081 (TDX)` を確認すること。

## 生成した quote.dat の使い道

この `quote.dat` をそのまま TEE Anchor に渡す（TDX 経路は今後実装）：

- `provision` … Quote 内 PCK 証明書から Chip ID（PPID）を抽出し、組織エンドースメント証明書を発行
- `verify`    … Quote のチェーン検証 + Chip ID の bit-for-bit 照合

SGX と同じく TDX も Chip ID は Quote 本体（TD Report）には含まれず、末尾の Certification Data に埋め込まれた PCK 証明書から抽出する点に注意（SEV-SNP のように Report 本体からは取れない）。

## 補足

- `report_data`（64B）の中身は Chip ID binding には無関係。鍵交換等とバインドしたい場合にハッシュを載せる枠として残してある。
- Ubuntu 24.04 既定カーネルでは RTMR2/3 への Extend に不具合があるが（カーネル 6.16+ で解消）、Quote 取得と PCK / Chip ID 抽出には影響しない。

# SGX 最小 Quote 取得サンプル

TEE Anchor の `provision` / `verify` に渡す **`quote.dat` を実機 SGX 上で 1 個生成するだけ**の最小サンプル。
Humane-RAFW-MAA の Quote 生成部分から、RA セッション・鍵交換・HTTP・JSON を全て剥がしてある。

> このサンプルは TEE Anchor 本体（Endorser/Verifier）の一部ではなく、**評価用に Attester 側の入力を作るためのハーネス**です。本体は生成済み `quote.dat` をファイル入力として消費するだけで、Enclave コードは持ちません。

## 構成

```
sgx_sample/
├── App/sample_app.cpp        # QE3 target info → REPORT → sgx_qe_get_quote → quote.dat
├── Enclave/
│   ├── sample_enclave.edl     # ecall_create_report のみ
│   ├── sample_enclave.cpp     # sgx_create_report を呼ぶだけ
│   └── Enclave.config.xml
├── Makefile
├── setup.sh                   # 環境構築の自動化（Intel APT リポジトリ + SDK .bin）
├── sgx_default_qcnl.conf      # 参考 QCNL 設定（Azure CVM 想定）
└── README.md
```

## 前提（実機側）

- Intel SGX 対応マシン（DCAP）。本サンプルは **Ubuntu 24.04 / Azure Confidential VM** を想定。
- カーネル 5.11+（in-kernel SGX ドライバ）。`/dev/sgx_enclave` が存在すること。
- 以下の環境構築は `setup.sh` で自動化済み（手動導入も可）。

## 環境構築

Intel 公式 APT リポジトリから SGX PSW / DCAP ランタイム・開発パッケージを、
SDK は公式 `.bin` インストーラから導入し、`/etc/sgx_default_qcnl.conf` 配置と
`aesmd` 再起動まで自動で行う。**sudo が必要**。

`make` コマンド自体が未導入のクリーン環境では、まず `setup.sh` を直接実行する
（スクリプト内で `build-essential` = `make` 含む を導入するため、ブートストラップを兼ねる）：

```sh
sudo ./setup.sh
```

`make` 導入済みなら Makefile 経由でもよい：

```sh
sudo apt-get install -y make   # 未導入の場合のみ。以降の make 利用を有効化
sudo make setup                # = sudo ./setup.sh （一括構築）
make check-env                 # = ./setup.sh --check （構築せず診断のみ）
```

主なオプション（環境変数で上書き）:

| 変数 | 既定 | 説明 |
|---|---|---|
| `QCNL_MODE` | `azure` | `keep` にすると `/etc/sgx_default_qcnl.conf` を上書きしない（自前 PCCS 等を使う場合） |
| `FORCE_SDK` | （無効） | `1` で SGXSDK を再インストール |
| `SGX_SDK_BIN_URL` | 自動探索 | SDK `.bin` の直 URL を指定（探索に失敗する場合） |
| `SDK_DISTRO` | `ubuntu24.04-server` | SDK `.bin` の distro フォルダ名 |

> QCNL が PCK collateral を取得できないと、Quote の Certification Data に
> PCK 証明書チェーンが入らず（cert key type != 5）、TEE Anchor で Chip ID を
> 取り出せない。Azure 以外（bare-metal + PCCS）では `QCNL_MODE=keep` で自前設定を温存するか、
> `/etc/sgx_default_qcnl.conf` を環境に合わせて編集すること。

## ビルドと実行

```sh
source /opt/intel/sgxsdk/environment   # SGX_SDK 等を設定（セッション毎に必要）
make                                   # enclave 署名 + sample_app
./sample_app                           # quote.dat を生成（既定の出力名）
# または
./sample_app my_quote.dat "hello"      # 出力名と report_data(最大64B) を指定
make run                               # ビルド込みで一括実行
```

成功すると以下が表示される：

```
Quote written: quote.dat (NNNN bytes)
cert key type : 5 (PCK_CERT_CHAIN: OK, PCK cert is embedded)
```

**`cert key type` が 5 であることを必ず確認**すること。5 以外（1/2/3 など）の場合、
Quote に PCK 証明書チェーンが埋め込まれておらず、TEE Anchor で PCK 証明書／Chip ID を
取り出せない（QCNL 設定や PCCS 到達性を見直す）。

## 生成した quote.dat の使い道

この `quote.dat` をそのまま TEE Anchor に渡す：

- `provision` … Quote 内 PCK 証明書から Chip ID を抽出し、組織エンドースメント証明書を発行
- `verify`    … Quote のチェーン検証 + Chip ID の bit-for-bit 照合

## 補足

- 既定は **DEBUG enclave + 1 段階署名**（鍵が無ければ `make` が `openssl genrsa -3 3072`
  で自動生成）。PCK 証明書／Chip ID は enclave のデバッグ状態に依存しないため、
  DEBUG enclave の Quote でも provision/verify には問題なく使える。
- シミュレーションモード（`make SGX_MODE=SIM`）では実際の Quote は生成できない
  （DCAP は HW を要求する）。Quote が必要なので **HW モードで実行**すること。
- `report_data` の中身は Chip ID binding には無関係。鍵交換等とバインドしたい場合に
  ハッシュを載せる枠として残してある。

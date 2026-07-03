# SGX Quote取得サンプル
TEE Anchorの動作確認に用いる事ができる、SGX Quoteを生成するためのサンプルコード。[Humane-RAFW-MAA](https://github.com/acompany-develop/Humane-RAFW-MAA)のコードからQuote取得部分を切り出す形で実装している。現時点では最小限のサンプルのみ提供としているため、最もQuoteを取得する難易度の低い、AzureのSGXインスタンス（DCsv3）での実行を前提としている。ベアメタル環境等で取得したい場合には、[Humane-RAFW-DCAP](https://github.com/iisec-suzaki/Humane-RAFW-DCAP)を改造しての利用も一考の事。

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

## 導入・ビルド手順
以下のコマンドを実行し環境構築を実施する。
```sh
sudo ./setup.sh
```

主なオプションは以下の通り：
| 変数 | 既定 | 説明 |
|---|---|---|
| `QCNL_MODE` | `azure` | `keep` にすると `/etc/sgx_default_qcnl.conf` を上書きしない（自前 PCCS 等を使う場合） |
| `FORCE_SDK` | （無効） | `1` で SGXSDK を再インストール |
| `SGX_SDK_BIN_URL` | 自動探索 | SDK `.bin` の直URLを指定（探索に失敗する場合） |
| `SDK_DISTRO` | `ubuntu24.04-server` | SDK `.bin` の distroフォルダ名 |

以下のコマンドによりビルドと実行を行う。
``` sh
source /opt/intel/sgxsdk/environment
make
./sample_app
```

出力ファイル名やReport Dataを指定したい場合には、`./sample_app`を以下のように実行する事もできる。
``` sh
./sample_app my_quote.dat "hello"
```

成功すると以下が表示される：
```sh
Quote written: quote.dat (NNNN bytes)
cert key type : 5 (PCK_CERT_CHAIN: OK, PCK cert is embedded)
```
`cert key type`が5でないとTEE Anchorにより正常にPPIDを取り出せないため、念の為確認する事。もし5でない場合は、`sgx_default_qcnl.conf`の設定にミスがある可能性がある。

実行の結果、`quote.dat`（または指定したファイル名のQuote）が生成され、これはTEE Anchor本体のREADME.mdで説明しているコマンドでは、この配置のものをそのまま使用する設定となっている。
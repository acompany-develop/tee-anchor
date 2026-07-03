# TD Quote取得サンプル
TEE Anchorの動作確認に用いる事ができる、TD Quoteを生成するためのサンプルコード。現時点では必要最小限のみの提供であるため、前提として`/dev/tdx_guest`がTDゲスト内に公開されている環境でのみ使用可能。具体的には、パラバイザによるvTPMを用いる方式を採用しているAzure TDXインスタンスでは使用できない。

動作確認はUbuntu 24.04 LTSを搭載した、GCPのTDXインスタンスで実施している。

## 構成
```
tdx_sample/
├── get_quote.c     # tdx_att_get_quote → quote.dat（version/tee_type を表示）
├── Makefile        # gcc -ltdx_attest（all/run/setup/check-env/clean）
├── setup.sh        # 環境構築の自動化（Intel APT リポジトリ + libtdx-attest 等）
└── README.md
```

## 導入・ビルド手順
以下のコマンドを実行し環境構築を実施する。
```sh
sudo ./setup.sh
```
以下のコマンドによりビルドと実行を行う。
``` sh
make
./get_quote
```

出力ファイル名やReport Dataを指定したい場合には、`./get_quote`を以下のように実行する事もできる。
``` sh
./get_quote my_quote.dat "hello"
```

成功すると以下が表示される：
```sh
TD Quote written: quote.dat (NNNN bytes)
  quote version : 4
  att key type  : 2 (ECDSA-P256)
  tee type      : 0x00000081 (TDX: OK)
```

実行の結果、`quote.dat`（または指定したファイル名のQuote）が生成され、これはTEE Anchor本体のREADME.mdで説明しているコマンドでは、この配置のものをそのまま使用する設定となっている。
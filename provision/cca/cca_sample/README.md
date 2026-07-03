# CCA Attestation Token取得サンプル（QEMU フルエミュレーション）
TEE Anchorの動作確認に用いる事ができる、CCAのAttestation Tokenを生成するためのサンプルコード。Arm CCAには2026/7現在実機が存在しないため、このToken取得サンプルはCCAのフルエミュレーション環境の構築から一通りを実施しTokenを取得する設計となっている。

具体的には、QEMU（TCG）上にRME スタック（TF-A + TF-RMM + Host Linux/KVM + Realm guest）を丸ごとビルドして起動し、そのRealm内でTokenを生成する。手順はLinaroの["Building an RME stack for QEMU"](https://gitlab.com/Linaro/cca-public/build-instructions)に準ずる。

## 構成
```
cca_sample/
├── setup.sh             # RME スタックの一括構築（prereqs → fetch → build）
├── Makefile             # setup.sh + QEMU 起動の薄いラッパ
├── drive-realm.py       # ★ヘッドレス自動取得（QEMU 起動→自動ログイン→token 保存）
├── get-cca-token.sh     # Realm guest 内で手動実行する場合：token 取得 + base64 出力（POSIX sh）
├── extract-cca-token.sh # 手動経路でホスト側：base64 を cca-token.cbor に復元
└── README.md
```

## 前提
- Ubuntu 24.04 (noble) / x86_64であるVM上にて動作確認済み。
- 十分なリソース: ビルドが本番。最低でも16 (v)CPU / 64GB RAM / 250–300GB SSD以上のリソースを推奨する。
- 外向きHTTPS（`git.codelinaro.org` ほか。数GBをダウンロード）。
- `sudo`（apt前提パッケージ導入時のみ）。
- 多重仮想化状態が生まれるため、実行完了まで全体的にかなり時間がかかる点に注意。

## 実行手順
以下のコマンドを実行し、CCAエミュレーション環境の構築とTokenの取得を実施する。
```sh
make setup
make token
```

実行の結果、`cca-token.cbor`が生成され、これはTEE Anchor本体のREADME.mdで説明しているコマンドでは、この配置のものをそのまま使用する設定となっている。

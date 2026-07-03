# SEV-SNP Attestation Report取得サンプル
TEE Anchorの動作確認に用いる事ができる、SEV-SNP Attestation Report（AR）を生成するためのサンプルコード。現時点では必要最小限のみの提供であるため、前提として`/dev/sev-guest`がCVMゲスト内に公開されている環境でのみ使用可能。具体的には、パラバイザによるvTPMを用いる方式を採用しているAzure SEV-SNPインスタンスでは使用できない。

## 構成
```
snp_sample/
├── get_attestation.sh    # 一括実行スクリプト
└── README.md
```

## 実行手順
以下のコマンドを実行し環境構築を実施する。
```sh
sudo ./get_attestation.sh
```
上手く動作しない場合には権限不足の可能性があるため、sudoを付与して実行する事。

## 実行による生成物一覧
| ファイル | 役割 |
|---|---|
| `report.bin` | Attestation Report（TEE Anchorへの入力。SGXの `quote.dat` に相当） |
| `request-data.txt` | Report要求に使った64B request data（参照用） |
| `certs/ark.pem` | AMD Root Key（自己署名 root） |
| `certs/ask.pem` | AMD SEV Key（intermediate） |
| `certs/vcek.pem` | VCEK |

これらの生成物は、TEE Anchor本体のREADME.mdで説明しているコマンドでは、この配置のものをそのまま使用する設定となっている。
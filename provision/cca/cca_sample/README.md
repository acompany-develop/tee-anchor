# Arm CCA Attestation Token 取得サンプル（QEMU フルエミュレーション）

TEE Anchor の CCA 経路（`provision` / `verify`）に渡す **CCA Attestation Token
(`cca-token.cbor`) を生成する**ためのサンプル。SGX の `sgx_sample`、TDX の
`tdx_sample`、SEV-SNP の `snp-sample` に対応する Arm CCA 版にあたる。

> このサンプルは TEE Anchor 本体（Endorser/Verifier）の一部ではなく、
> **評価用に Attester 側の入力を作るためのハーネス**です。本体は生成済みの
> `cca-token.cbor` をファイル入力として消費するだけで、エミュレータには触れません。

**他 TEE との決定的な違い**: Arm CCA は実機（Armv9-A + RME 搭載 CPU）が市場に存在
しないため、Quote/Report を実機から取るのではなく、**QEMU(TCG) 上に RME スタック
（TF-A + TF-RMM + Host Linux/KVM + Realm guest）を丸ごとビルドして起動**し、その
Realm 内で token を生成する。手順は Linaro *"Building an RME stack for QEMU"*
（OP-TEE ビルド環境方式）に準拠し、同梱の [`cca-ra-doc.pdf`](../../../cca-ra-doc.pdf)
（Arm CCA RA 調査）で実証済みの recipe をそのまま自動化してある。

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

token の取得には 2 通りある:

- **`make token`（推奨・無人）**: `drive-realm.py` が QEMU を直接 server モードで起動し、
  外側 Host と nested Realm に自動ログインして `cca-token.cbor` を保存する。CI 向き。
- **手動**: `make run` で QEMU を起動し、コンソールを人間が操作する（下記「手動経路」）。

## 前提（ホスト側）

- **Ubuntu 24.04 (noble) / x86_64**（cca-ra-doc.pdf の検証環境と同一）。
- **十分なリソース**: ビルドが本番。推奨 **16 vCPU / 64GB RAM / 250–300GB SSD**。
  最低でも 8 vCPU / 32GB / 200GB。TCG なので Confidential Computing 機能（TDX/SEV）は
  **不要**＝プレーンな汎用 VM で動く。
- 外向き HTTPS（`git.codelinaro.org` ほか。数 GB をダウンロード）。
- `sudo`（apt 前提パッケージ導入時のみ）。
- 実行はとにかく遅い（QEMU on QEMU。Realm 起動に数分）。リソース増強はビルド時間
  短縮と OOM 回避が主目的で、実行速度は劇的には変わらない。

## クイックスタート

```sh
cd provision/cca/cca_sample

# 1) 一括構築（前提パッケージ + ソース取得 + ビルド）。数十GB・長時間。
make setup
#   段階実行したい場合:
#     sudo ./setup.sh --prereqs   # apt のみ
#     ./setup.sh --fetch          # repo init + sync
#     ./setup.sh --build          # make toolchains + make
#     ./setup.sh --check          # 構築状況の診断

# 2) token を無人取得（QEMU 起動→Host/Realm 自動ログイン→cca-token.cbor 保存）
make token
#   → ./cca-token.cbor が保存される（TCG 二段ブートのため十数分〜数十分）
#   → 進捗: tail -f $HOME/cca/realm-run/{qemu,fw,host,realm}.log
```

`make token` の中身（`drive-realm.py`）は、後述の手動経路と同じことを自動化したもの。
QEMU を **serial server モード**で直接起動し（`make run-only` 経由だと内部の `nc -z`
ポート探査が QEMU の本接続を奪うため）、4 コンソールを常時 drain しつつ（TCG は
シングルスレッドなので 1 つでも詰まると VM 全体が停止する）、Host→Realm に順にログイン
して `cca-workload-attestation report` を実行、結果を base64 で吸い出して保存する。

## 手動経路：Realm guest の起動と token 取得

`make run` で 4 コンソール（Firmware/Secure/Host/Realm）を開き、人手で操作する場合。

`make run` で上がった **Host OS 上で、さらに QEMU を実行して Realm guest を起動**する
（ビルド時に `cca/` が `/mnt` にマウント済み。`cca-ra-doc.pdf` の recipe どおり）:

```sh
## (Host コンソール)
qemu-system-aarch64 \
    -M confidential-guest-support=rme0 \
    -object rme-guest,id=rme0,measurement-algorithm=sha512 \
    -nodefaults \
    -chardev stdio,mux=on,id=virtiocon0,signal=off \
    -device virtio-serial-pci \
    -device virtconsole,chardev=virtiocon0 \
    -mon chardev=virtiocon0,mode=readline \
    -kernel /mnt/out/bin/Image \
    -initrd /mnt/out-br/images/rootfs.cpio \
    -device virtio-net-pci,netdev=net0,romfile= \
    -netdev user,id=net0 \
    -cpu host -M virt -enable-kvm -M gic-version=3,its=on \
    -smp 2 -m 512M -nographic \
    -append console=hvc0 < /dev/hvc1 >/dev/hvc1
```

Realm コンソールに login プロンプトが出たら root でログイン（パスワード不要）。
**Realm 内で token を取得**する（`get-cca-token.sh` の中身を貼り付けるか、`report` を直接）:

```sh
## (Realm コンソール)
cca-workload-attestation report
#   → Platform/Realm トークンが JSON で表示され、CBOR が cca-token.cbor に保存される
base64 cca-token.cbor
#   → 出力された base64 をホストへコピー
```

ホスト側（QEMU を起動している側）で復元:

```sh
## (ホスト)
./extract-cca-token.sh < pasted.txt     # マーカー込みで貼り付けたテキスト or ログから
#   → cca-token.cbor を復元
```

## 取得できる token について（重要）

cca-ra-doc.pdf の分析より、本 QEMU 環境（`cca/v10`）で得られる token は以下:

- **バージョン**: RATS CCA Token **v01（CBOR tag:399、EAT Collection wrapper）**。
  v02 では wrapper が CMW(tag:907) に変わるが本環境は v01。`evcli` も v01 準拠。
- **構造**: `cca-platform-token`（CPAK 署名）+ `cca-realm-delegated-token`（RAK 署名）の
  2 サブトークン。両者は **Platform の `cca-platform-challenge` = RAK 公開鍵
  (`cca-realm-public-key`) のハッシュ** で暗号学的に bind されている（Delegated Model）。
- **Chip ID に使うクレーム**: **`cca-platform-instance-id`**（PAK の一意識別子＝個体
  シリアル相当）。`cca-platform-implementation-id` は実装クラス共通値（proxy 検出に
  使えない）なので採らない。SGX で FMSPC でなく PPID を選んだのと同じ判断。
- **信頼根**: CCA に X.509 は無い。Platform Token は CPAK 公開鍵で検証する（実機では
  CoRIM 等で endorsement されるが、本エミュでは固定 dev 鍵）。**TEE Anchor は CPAK
  公開鍵を pin する**（Intel SGX Root pubkey / AMD ARK の pin と同型）。
- **注意（エミュ固有）**: QEMU 環境の Platform Token は TF-A の
  `qemu_plat_attest_token.c` に **ハードコードされたダミー値**。Linaro のテスト用
  Veraison エンドポイントにはこのダミーに対応する endorsement が登録済みで、検証すると
  Platform 側は全カテゴリ affirming になる。よって本サンプルで得る instance-id 等は
  「実 HW 識別子」ではなく固定値である点を、論文・評価では明記すること。

## TEE Anchor の CCA provision/verify での使われ方（予定）

```sh
# （実装後）token から instance-id を抽出して endorsement を発行
tee-anchor provision --tee-type cca \
    --token cca-token.cbor \
    --cpak  <CPAK公開鍵をpin> \
    --ca-key ca.key --ca-cert ca.crt --out cca_endorsement.crt
```

検証フロー（既存 TEE と対称）: CPAK pin → `COSE_Sign1`(Platform Token) の ECDSA 署名
検証 →（任意で Realm Token + binding 検証）→ 通過後に `cca-platform-instance-id` を
抽出 → `ChipIdBinding{teeType=armCca(3)}` を組織 CA が X.509 で発行 → verify は Chip ID
を bit-for-bit 照合。後半（組織 endorsement + binding）は SGX/TDX/SNP と完全に共通。

> CBOR/COSE のパースには新依存が 1 つ要る（QCBOR + t_cose、または libcbor + 手書き
> COSE_Sign1 + OpenSSL）。検証ロジックは Veraison の `ccatoken` / `evcli` が参照実装。

## 参考

- 同梱 [`cca-ra-doc.pdf`](../../../cca-ra-doc.pdf) — Arm CCA RA 調査（本サンプルの一次資料）
- Linaro: *Building an RME stack for QEMU*（OP-TEE build environment）
- IETF: `draft-ffm-rats-cca-token-01`（claim 定義）
- Veraison: `evcli` / `ccatoken` / `ear`（token 検証の参照実装）

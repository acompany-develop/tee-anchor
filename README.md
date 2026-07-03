# TEE Anchor: Cross-TEE Organizational Endorsement for Mitigating TEE Physical Attacks
本リポジトリは、任意の組織が独自に形成可能なPKIベースの追加の認証・検証機構により、TEE（Trusted Execution Environment）に対するTEE.failやBattering RAMといった物理攻撃を間接的に予防する事のできるスタンドアロンCLIツール「TEE Anchor」を提供する。

TEE Anchorは、各種TEEのAttestation Report（AR）またはそれを認証するTEEベンダ発行の証明書（例：Intel SGX/TDXであればPCK Cert）から、そのハードウェア固有のID（Chip ID）を抽出する。一方、組織CAは予め管理対象のChip IDに対し、組織ルートCAをトラストアンカーとした組織リーフ証明書を発行（プロビジョニング）している。この発行した組織証明書内のChip IDと、ARまたはTEEベンダ証明書から抽出したChip IDを比較する事で、真にその組織に当該Attesterマシンが属しているかを検証できる。これにより、例えばマシンを物理的に厳重に管理している組織の管理下にそのマシンがある事を保証する事ができ、ひいてはTEE.failのような物理攻撃が不可能な環境下にある事を検証者は確信する事ができる。

## 導入の前提条件
* OS: Ubuntu 24.04 LTS（他のLinuxも可能であるが、動作確認済みであるのはこれのみ）
* `g++` 11+または `clang++` 14+（C++17必須）
* OpenSSL 3.x

## 導入・ビルド手順
* 前提パッケージのインストールを実施する。
    ```sh
    sudo apt-get install -y build-essential libssl-dev
    ```

* 以下のコマンドを実行し、`tee-anchor`バイナリを生成する。
    ```sh
    make
    ```

* 生成物を削除する場合には以下のコマンドを実行する。
    ```sh
    make clean
    ```

## サブコマンド一覧
| サブコマンド | 説明 |
|---|---|
| `ca-init`   | 組織ルートCA鍵を生成し、それを用いて組織ルートCA証明書を発行する。 |
| `provision` | ARまたはTEEベンダ証明書からChip IDを抽出し、組織CAで署名した組織リーフ証明書を発行する。SGX/TDXの場合はPPID、SEV-SNPの場合はCHIP_ID、CCAの場合はcca-platform-instance-idを用いる。 |
| `verify`    | ARまたはTEEベンダ証明書、組織リーフ証明書、組織ルートCA証明書を用いてChip IDの一致を確認する。任意でCRLによる失効確認も可能。 |
| `revoke`    | 組織証明書のシリアルを失効リストDBに追加する。 |
| `crl-issue` | 失効リストDBからX.509 CRLを発行する。 |

各サブコマンドの詳細は`./tee-anchor <subcmd> --help`で確認可能。

## クイックスタート
以下に、SGX、TDX、SEV-SNP、CCAそれぞれの場合における、各サブコマンドの一連の確認手順の説明を行う。

### 共通処理（組織CAの初期化）
各処理に入る前に、以下のコマンドを実行する事で組織CAの初期化を実施する。以降、全ての操作においてこの初期化済み組織CAが存在する事を前提とする。
```sh
W=/tmp/tea_demo
rm -rf "$W" && mkdir -p "$W"

./tee-anchor ca-init --out-dir "$W"
```

### SGX
前提として、SGX Quoteを`provision/sgx/sgx_sample/quote.dat`に配置しておく。SGX Quote取得用のスクリプトを用意しているため、必要であれば`provision/sgx/sgx_sample/README.md`上の説明を参照の上実行の事。これは、`sgx_sample`フォルダ内で以下のような手順で実行するとQuoteを取得する事ができる：
```sh
sudo ./setup.sh
source /opt/intel/sgxsdk/environment
make
./sample_app
```
デフォルトではAzure SGX VM用であるが、`sgx_default_qcnl.conf`やPCCSの設定等行えば他の環境でも利用可能。詳細は[Humane-RAFW-DCAP](https://github.com/iisec-suzaki/Humane-RAFW-DCAP)も参照の事。

まず、失効処理抜きでの組織CA初期化、プロビジョニング、検証を確認する方法を以下に示す。
``` sh
# Quoteから組織リーフ証明書を発行（プロビジョニング）
./tee-anchor provision \
    --quote   provision/sgx/sgx_sample/quote.dat \
    --ca-key  "$W/ca.key" \
    --ca-cert "$W/ca.crt" \
    --out     "$W/endorsement.crt"

# 検証を実施する。成功すればExit Codeは0。
./tee-anchor verify \
    --quote    provision/sgx/sgx_sample/quote.dat \
    --org-cert "$W/endorsement.crt" \
    --org-ca   "$W/ca.crt"
echo "exit=$?"
```

成功時の出力は以下の通り：
```
verify: OK
  tee_type       : sgx (0)
  chip_id (hex)  : 00112233445566778899aabbccddeeff
  ...
```

失効追加、失効リスト払い出し、失効確認付き検証を試すには、プロビジョニングまでは実施した状態で以下の通り：
``` sh
# 失効リストDBにエントリ追加
./tee-anchor revoke \
    --ca-cert "$W/ca.crt" \
    --cert    "$W/endorsement.crt" \
    --reason  keyCompromise

# DBからCRLを発行
./tee-anchor crl-issue \
    --ca-key  "$W/ca.key" \
    --ca-cert "$W/ca.crt" \
    --out     "$W/crl.pem"

# 失効確認付き検証。失効を検出してExit Codeが24となる。
./tee-anchor verify \
    --quote    provision/sgx/sgx_sample/quote.dat \
    --org-cert "$W/endorsement.crt" \
    --org-ca   "$W/ca.crt" \
    --crl      "$W/crl.pem"
echo "exit=$?"   # → 24
```
`--crl`サブコマンドは任意指定であるため、指定しなければ前述の検証例の通り失効確認は実施されない。

他のTEEにも共通するが、実際には検証は従来のRAのAR検証後に追加で実施する。例えば従来RA検証完了後、サブプロセス的に`tee-anchor`を呼び出し、組織による認証がされているかを追加で確認するようなイメージである。

### TDX
TDXはQuote（AR）の構造以外は基本的にSGXと同一であるため、SGXとほぼ同じようにして一連の実行を行う事ができる。

前提として、`provision/tdx/tdx_sample/quote.dat`にTD Quoteを配置しておく。これも同梱のQuote生成サンプルを用いて生成できる。詳細は`provision/tdx/tdx_sample/README.md`を参照。
```sh
cd provision/tdx/tdx_sample
sudo ./setup.sh
make && sudo ./get_quote
cd -
```
ただし、`/dev/tdx_guest`がゲストに公開されているTDでないとこのサンプルは使用できない。例えばCanonicalの手順に従いベアメタルでビルドしたTDや、GCPのTDでは使用可能であるが、Azureにおいてはこれが公開されていないため使用不可。

以下のコマンドにより、TDX用のプロビジョニング及び検証を実施できる。
```sh
./tee-anchor provision --tee-type tdx \
    --quote   provision/tdx/tdx_sample/quote.dat \
    --ca-key  "$W/ca.key" \
    --ca-cert "$W/ca.crt" \
    --out     "$W/tdx_endorsement.crt"

./tee-anchor verify --tee-type tdx \
    --quote    provision/tdx/tdx_sample/quote.dat \
    --org-cert "$W/tdx_endorsement.crt" \
    --org-ca   "$W/ca.crt"
echo "exit=$?"   # → 0
```

失効追加・CRL払い出し・失効の追加検証は、SGXと同様に実施可能である。

### SEV-SNP
SEV-SNPの場合も、前提としてARを用意しておく必要がある。こちらも同梱のサンプルコードにより以下のように生成できる。詳細は`provision/sev-snp/snp_sample/README.md`を参照。
```sh
cd provision/sev-snp/snp_sample
./get_attestation.sh # report.bin と certs/{ark,ask,vcek}.pem を生成
cd -
```

プロビジョニングと検証は以下のように実施できる。用語の違いから、SGX/TDXと異なり、`--quote`サブコマンド相当が`--report`、そしてSEV-SNPではTEEベンダ証明書が別添である事から追加で`--certs`サブコマンドが必要となる点に注意。
```sh
./tee-anchor provision --tee-type snp \
    --report provision/sev-snp/snp_sample/report.bin \
    --certs  provision/sev-snp/snp_sample/certs \
    --ca-key  "$W/ca.key" \
    --ca-cert "$W/ca.crt" \
    --out     "$W/snp_endorsement.crt"
    
./tee-anchor verify --tee-type snp \
    --report   provision/sev-snp/snp_sample/report.bin \
    --certs    provision/sev-snp/snp_sample/certs \
    --org-cert "$W/snp_endorsement.crt" \
    --org-ca   "$W/ca.crt"
echo "exit=$?"   # → 0
```
失効関連処理に関してはSGXやTDXと同様。

### CCA
CCAの場合は2026/6現在実機が存在しないため、QEMUによるフルエミュレーション環境上のRealmからToken（AR）を取得する事になる。TokenはCBOR方式となっており、これは決め打ちのCPAK秘密鍵で署名されるため、対応するCPAK公開鍵をハードコーディングしそれにて検証する方式としている。

まずはこのTokenが必要であるため、以下の同梱のスクリプトを用いてTokenを生成する。詳細は`provision/cca/cca_sample/README.md`を参照。
```sh
cd provision/cca/cca_sample
make setup # 初回のみ。かなりの時間がかかる。
make token
cd -
```
特にクラウド等のVM内で実行する場合、VM内でQEMUのフルエミュレーションを実行しさらにその中でRealmを動かすという多重Nested仮想化状態となるため、`make setup`に極めて長い時間がかかる。VMの場合かなり多めのvCPUリソースを積むか、ベアメタル上で実施する事を推奨。

プロビジョニングと検証は以下のように実施できる。用語の違いから、SGX/TDXと異なり、`--quote`サブコマンド相当が`--token`である点に注意。
``` sh
./tee-anchor provision --tee-type cca \
    --token   provision/cca/cca_sample/cca-token.cbor \
    --ca-key  "$W/ca.key" \
    --ca-cert "$W/ca.crt" \
    --out     "$W/cca_endorsement.crt"

./tee-anchor verify --tee-type cca \
    --token    provision/cca/cca_sample/cca-token.cbor \
    --org-cert "$W/cca_endorsement.crt" \
    --org-ca   "$W/ca.crt"
echo "exit=$?"   # → 0
```
失効関連処理は他のTEEと同様。

## verifyサブコマンドのExit Code一覧
| code | 意味 |
|---:|---|
| 0  | 正常終了（検証成功） |
| 20 | ARまたはTEEベンダ証明書の署名検証の失敗 |
| 21 | 組織証明書チェーン検証の失敗（CA不一致等） |
| 22 | **Chip ID 不一致** |
| 24 | 組織CRLにより組織リーフ証明書が失効済み |
| 30 | I/O / 内部エラー |

## ディレクトリ構成
```
tee-anchor/
├── tee_anchor.cpp              main: サブコマンド dispatch
├── Makefile
├── common/                     共有ヘッダ (RAII, 例外, I/O, PKI ユーティリティ)
├── ca/                         ca-init / revoke / crl-issue
├── binding/                    ChipIdBinding 拡張の DER エンコード/デコード
├── provision/                  provision サブコマンド (+ TEE 固有処理)
│   ├── sgx/
│   │   ├── sgx_provision.{hpp,cpp}      Quote パース + PCK chain 検証 + PPID 抽出
│   │   ├── intel_sgx_root_pubkey.hpp    Intel SGX Root CA 公開鍵 (QvE と同値)
│   │   └── sgx_sample/                  Quote 取得用ミニサンプル
│   ├── tdx/
│   │   ├── tdx_provision.{hpp,cpp}      TD Quote(v4/v5) パース + PCK chain 抽出 (検証/PPID は sgx 再利用)
│   │   └── tdx_sample/                  TD Quote 取得サンプル (libtdx_attest)
│   ├── sev-snp/
│   │   ├── snp_provision.{hpp,cpp}      Report パース + ARK pin/チェーン/Report 署名検証 + CHIP_ID 抽出
│   │   ├── amd_ark_pubkeys.hpp          AMD ARK pin (Milan/Genoa/Turin の SPKI SHA-384)
│   │   └── snp_sample/                  Report/VCEK 取得サンプル (snpguest ラッパ; 証拠生成用)
│   └── cca/
│       ├── cca_provision.{hpp,cpp}      CCA token(CBOR/COSE) パース + CPAK pin で検証 + instance-id 抽出
│       ├── cca_cpak_pubkey.hpp          CPAK pin (QEMU dev 鍵 = TF-M cca_platform.pem, P-384)
│       └── cca_sample/                  CCA token 取得サンプル (QEMU RME スタック + headless driver)
├── verify/                     verify サブコマンド
└── docs/                       設計ドキュメント
```

性能評価に使用したベンチマークツール及びそのREADME.mdも同梱しているが、整理が全くできておらず、README.mdもClaudeに記述させたものであるため、あくまでも参考用としてのみの目的での同梱である。

## ライセンス
本リポジトリはMITライセンスとする。一部で参照している[Humane-RAFW-MAA](https://github.com/acompany-develop/Humane-RAFW-MAA)や[Humane-RAFW-DCAP](https://github.com/iisec-suzaki/Humane-RAFW-DCAP)については、使用箇所をソース内で明記の上そちらのMITライセンスに準拠する。
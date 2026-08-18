# TEE Anchor: Cross-TEE Organizational Endorsement for Mitigating TEE Physical Attacks

> **Note:** This document is provided in English first. The original Japanese version is available in the latter half of this file — see [日本語版（Japanese）](#日本語版japanese).
>
> **注記:** 本ドキュメントは前半が英語版、後半が日本語版となっている。日本語版は[こちら](#日本語版japanese)を参照の事。

This repository provides **TEE Anchor**, a standalone CLI tool that indirectly mitigates physical attacks against TEEs (Trusted Execution Environments) — such as TEE.fail and Battering RAM — by means of an additional authentication/verification mechanism built on a PKI that any organization can establish independently.

TEE Anchor extracts a hardware-unique identifier (Chip ID) from the Attestation Report (AR) of a given TEE, or from the TEE-vendor-issued certificate that authenticates it (e.g. the PCK Cert in the case of Intel SGX/TDX). Separately, the organizational CA has issued (provisioned) in advance an organizational leaf certificate for each Chip ID under its management, rooted at the organizational root CA as the trust anchor. By comparing the Chip ID recorded in that issued organizational certificate against the Chip ID extracted from the AR or the TEE vendor certificate, a verifier can confirm that the Attester machine genuinely belongs to that organization. This makes it possible to guarantee, for example, that the machine is under the control of an organization that physically manages its machines under strict conditions, and thus lets the verifier be confident that the machine resides in an environment where physical attacks such as TEE.fail are infeasible.

## Prerequisites

* OS: Ubuntu 24.04 LTS (other Linux distributions may work, but only this one has been verified)
* `g++` 11+ or `clang++` 14+ (C++17 required)
* OpenSSL 3.x

## Setup and Build

* Install the prerequisite packages.
    ```sh
    sudo apt-get install -y build-essential libssl-dev
    ```

* Run the following command to produce the `tee-anchor` binary.
    ```sh
    make
    ```

* To remove the build artifacts, run the following command.
    ```sh
    make clean
    ```

## Subcommands

| Subcommand | Description |
|---|---|
| `ca-init`   | Generates the organizational root CA key and uses it to issue the organizational root CA certificate. |
| `provision` | Extracts the Chip ID from an AR or a TEE vendor certificate and issues an organizational leaf certificate signed by the organizational CA. The PPID is used for SGX/TDX, the CHIP_ID for SEV-SNP, and the cca-platform-instance-id for CCA. |
| `verify`    | Confirms that the Chip IDs match, using an AR or TEE vendor certificate, the organizational leaf certificate, and the organizational root CA certificate. Optionally also performs a revocation check via a CRL. |
| `revoke`    | Adds the serial number of an organizational certificate to the revocation list DB. |
| `crl-issue` | Issues an X.509 CRL from the revocation list DB. |

Details of each subcommand can be found via `./tee-anchor <subcmd> --help`.

## Quick Start

The following describes, for each of SGX, TDX, SEV-SNP, and CCA, an end-to-end walkthrough of the subcommands.

### Common Step (Initializing the Organizational CA)

Before proceeding to each of the flows below, initialize the organizational CA by running the following commands. All subsequent operations assume that this initialized organizational CA exists.

```sh
W=/tmp/tea_demo
rm -rf "$W" && mkdir -p "$W"

./tee-anchor ca-init --out-dir "$W"
```

### SGX

As a prerequisite, place an SGX Quote at `provision/sgx/sgx_sample/quote.dat`. A script for obtaining an SGX Quote is included; if needed, follow the instructions in `provision/sgx/sgx_sample/README.md` before running it. The Quote can be obtained by running the following steps inside the `sgx_sample` directory:

```sh
sudo ./setup.sh
source /opt/intel/sgxsdk/environment
make
./sample_app
```

By default this targets Azure SGX VMs, but it can also be used in other environments by configuring `sgx_default_qcnl.conf`, a PCCS, and so on. For details, see also [Humane-RAFW-DCAP](https://github.com/iisec-suzaki/Humane-RAFW-DCAP).

First, here is how to exercise organizational CA initialization, provisioning, and verification without revocation handling.

``` sh
# Issue an organizational leaf certificate from the Quote (provisioning)
./tee-anchor provision \
    --quote   provision/sgx/sgx_sample/quote.dat \
    --ca-key  "$W/ca.key" \
    --ca-cert "$W/ca.crt" \
    --out     "$W/endorsement.crt"

# Perform verification. On success the exit code is 0.
./tee-anchor verify \
    --quote    provision/sgx/sgx_sample/quote.dat \
    --org-cert "$W/endorsement.crt" \
    --org-ca   "$W/ca.crt"
echo "exit=$?"
```

The output on success looks like this:

```
verify: OK
  tee_type       : sgx (0)
  chip_id (hex)  : 00112233445566778899aabbccddeeff
  ...
```

The `chip_id` shown here has been replaced with a placeholder value. In practice a different value is printed for each execution environment.

To try adding a revocation, issuing a revocation list, and verification with a revocation check, start from the state where provisioning has been completed and proceed as follows:

``` sh
# Add an entry to the revocation list DB
./tee-anchor revoke \
    --ca-cert "$W/ca.crt" \
    --cert    "$W/endorsement.crt" \
    --reason  keyCompromise

# Issue a CRL from the DB
./tee-anchor crl-issue \
    --ca-key  "$W/ca.key" \
    --ca-cert "$W/ca.crt" \
    --out     "$W/crl.pem"

# Verification with a revocation check. The revocation is detected and the exit code becomes 24.
./tee-anchor verify \
    --quote    provision/sgx/sgx_sample/quote.dat \
    --org-cert "$W/endorsement.crt" \
    --org-ca   "$W/ca.crt" \
    --crl      "$W/crl.pem"
echo "exit=$?"   # → 24
```

The `--crl` option is optional; if it is not specified, no revocation check is performed, as in the earlier verification example.

As is also the case for the other TEEs, in practice this verification is performed as an additional step after conventional RA-based AR verification. For example, once conventional RA verification has completed, `tee-anchor` is invoked as a subprocess to additionally confirm that the machine has been endorsed by the organization.

### TDX

Apart from the structure of the Quote (AR), TDX is essentially identical to SGX, so the whole flow can be run in almost the same way as for SGX.

As a prerequisite, place a TD Quote at `provision/tdx/tdx_sample/quote.dat`. This too can be generated with the bundled Quote generation sample. For details, see `provision/tdx/tdx_sample/README.md`.

```sh
cd provision/tdx/tdx_sample
sudo ./setup.sh
make && sudo ./get_quote
cd -
```

Note, however, that this sample can only be used on a TD where `/dev/tdx_guest` is exposed to the guest. For example, it can be used on a TD built on bare metal following Canonical's procedure, or on a GCP TD, but not on Azure, where this device is not exposed.

Provisioning and verification for TDX can be performed with the following commands.

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

Adding revocations, issuing CRLs, and the additional revocation check can be performed in the same way as for SGX.

### SEV-SNP

For SEV-SNP as well, an AR must be prepared in advance. It can likewise be generated with the bundled sample code as follows. For details, see `provision/sev-snp/snp_sample/README.md`.

```sh
cd provision/sev-snp/snp_sample
./get_attestation.sh # generates report.bin and certs/{ark,ask,vcek}.pem
cd -
```

Provisioning and verification can be performed as follows. Note that, due to differences in terminology, the equivalent of `--quote` is `--report` unlike SGX/TDX, and because the TEE vendor certificates are supplied separately for SEV-SNP, an additional `--certs` option is required.

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

Revocation-related operations are the same as for SGX and TDX.

### CCA

For CCA, as of June 2026 no real hardware exists, so the Token (AR) is obtained from a Realm running on a full-emulation environment provided by QEMU. The Token is in CBOR format and is signed with a fixed, predetermined CPAK private key, so the corresponding CPAK public key is hardcoded and used for verification.

Since this Token is required first, generate it using the bundled script below. For details, see `provision/cca/cca_sample/README.md`.

```sh
cd provision/cca/cca_sample
make setup # first time only; takes a considerable amount of time
make token
cd -
```

In particular, when running inside a cloud VM or similar, QEMU full emulation runs inside the VM and a Realm runs inside that in turn, resulting in multiply nested virtualization, so `make setup` takes an extremely long time. On a VM it is recommended to allocate a fairly generous amount of vCPU resources, or to run this on bare metal.

Provisioning and verification can be performed as follows. Note that, due to differences in terminology, the equivalent of `--quote` is `--token` unlike SGX/TDX.

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

Revocation-related operations are the same as for the other TEEs.

## Exit Codes of the `verify` Subcommand

| code | Meaning |
|---:|---|
| 0  | Normal termination (verification succeeded) |
| 20 | Signature verification of the AR or TEE vendor certificate failed |
| 21 | Organizational certificate chain verification failed (e.g. CA mismatch) |
| 22 | **Chip ID mismatch** |
| 24 | The organizational leaf certificate has been revoked by the organizational CRL |
| 30 | I/O / internal error |

## Directory Layout

```
tee-anchor/
├── tee_anchor.cpp              main: subcommand dispatch
├── Makefile
├── common/                     shared headers (RAII, exceptions, I/O, PKI utilities)
├── ca/                         ca-init / revoke / crl-issue
├── binding/                    DER encoding/decoding of the ChipIdBinding extension
├── provision/                  provision subcommand (+ TEE-specific processing)
│   ├── sgx/
│   │   ├── sgx_provision.{hpp,cpp}      Quote parsing + PCK chain verification + PPID extraction
│   │   ├── intel_sgx_root_pubkey.hpp    Intel SGX Root CA public key (identical to QvE's)
│   │   └── sgx_sample/                  minimal sample for obtaining a Quote
│   ├── tdx/
│   │   ├── tdx_provision.{hpp,cpp}      TD Quote (v4/v5) parsing + PCK chain extraction (verification/PPID reuse the sgx code)
│   │   └── tdx_sample/                  sample for obtaining a TD Quote (libtdx_attest)
│   ├── sev-snp/
│   │   ├── snp_provision.{hpp,cpp}      Report parsing + ARK pin/chain/Report signature verification + CHIP_ID extraction
│   │   ├── amd_ark_pubkeys.hpp          AMD ARK pins (SPKI SHA-384 for Milan/Genoa/Turin)
│   │   └── snp_sample/                  sample for obtaining a Report/VCEK (snpguest wrapper; for evidence generation)
│   └── cca/
│       ├── cca_provision.{hpp,cpp}      CCA token (CBOR/COSE) parsing + verification with the CPAK pin + instance-id extraction
│       ├── cca_cpak_pubkey.hpp          CPAK pin (QEMU dev key = TF-M cca_platform.pem, P-384)
│       └── cca_sample/                  sample for obtaining a CCA token (QEMU RME stack + headless driver)
├── verify/                     verify subcommand
└── docs/                       design documents
```

The benchmark tool used for the performance evaluation and its README.md are also bundled, but they have not been organized at all and the README.md was written by Claude, so they are included strictly for reference purposes only.

## License

This repository is licensed under the MIT License. For the parts that reference [Humane-RAFW-MAA](https://github.com/acompany-develop/Humane-RAFW-MAA) and [Humane-RAFW-DCAP](https://github.com/iisec-suzaki/Humane-RAFW-DCAP), the relevant locations are noted in the source and those parts conform to their respective MIT Licenses.

---

# 日本語版（Japanese）

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
`chip_id`は仮の値に置き換えてある。実際には実行環境ごとに異なる値が出力される。

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

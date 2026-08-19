# Protocol Design

## 全体像

TEE Anchor は以下の 2 つのフェーズから構成される：

1. **Provisioning Phase**: 組織が CA を立ち上げ、管理下マシンごとに組織エンドースメント証明書を発行する
2. **Verification Phase**: Relying Party が Quote と組織エンドースメント証明書を併せて検証する

```
[Provisioning]
  Organization Root CA
        │
        ├── (sign) ──> Org Endorsement Cert for Machine A (Chip ID: AAAA...)
        ├── (sign) ──> Org Endorsement Cert for Machine B (Chip ID: BBBB...)
        └── (sign) ──> ...

[Verification]
  Verifier receives:
    - Quote (contains PCK/VCEK Cert, which contains Chip ID)
    - Org Endorsement Cert (contains Chip ID in critical extension)
  Verifier checks:
    1. Quote signature chain (Intel/AMD Root CA)
    2. Org Endorsement Cert signature chain (Organization Root CA)
    3. Chip ID in Quote == Chip ID in Org Endorsement Cert  ← KEY CHECK
```

## PKI 階層

### Phase 1: フラット階層（root のみ）

```
Organization Root CA  ──(直接署名)──>  Org Endorsement Cert (Machine X)
```

Phase 1 では中間 CA を挟まず、組織 Root CA がエンドースメント証明書を直接署名する。理由：

- PoC の主張は Chip ID binding であり、PKI 階層の深さとは独立変数
- 中間 CA 階層は後付けが purely additive（root cert を再発行せず済む設計にしておく）
- OpenSSL の `X509_verify_cert` は任意深度のチェーンを扱うため、Phase 2 で intermediate を挟む拡張時に検証側コードはほぼ無改修

Phase 1 の root cert は `BasicConstraints CA:TRUE` を pathLenConstraint **なし**で発行する。これにより Phase 2 で intermediate を増やす際に root の再発行が不要となる。

### Phase 2 以降の拡張案

- 複数 DC / 環境（prod/staging）ごとに intermediate CA を切る
- Root CA 鍵をオフライン保管し、intermediate のみオンラインで日次発行に使用

## Chip ID の抽出

### Intel SGX/TDX

- PCK Cert の **SGX Extensions**（OID `1.2.840.113741.1.13.1`）内、`PPID`（OID `1.2.840.113741.1.13.1.1`、16 バイトの OCTET STRING）を Chip ID として採用する。
- 実機（Azure DCsv3、SGX SDK + DCAP）で生成した Quote の PCK leaf 証明書に **平文 PPID が含まれることを確認済み**。Phase 1 では `Chip ID = PPID(16B)` で確定する。
- **FMSPC（OID `....1.4`）/ PCEID（OID `....1.3`）は binding に含めない**。
  - PPID と同じ chip の属性で、PPID が一致すれば論理的に従属して一致するため、独立した防御価値が無い
  - 特に PCEID は PCE 更新で変動し得るため、固定すると再プロビジョニングを強制する運用負債
  - 論文の脅威モデル説明上も「Chip ID = PPID」という一行で済む方が清潔
- 環境差で PPID が暗号化形式 / 0 埋めで提供される場合のフォールバック（PCK leaf の Subject Key Identifier 等）は Phase 2 以降で検討。実装上は all-zero PPID を検知時に警告する。

#### TDX 固有: TD Quote のパース（実装済 / provision）

PCK 証明書・PPID・SGX Extension・チェーン検証（Intel SGX Root CA 公開鍵 pin）は **SGX と完全に共通**で、`sgx::verify_pck_chain` / `sgx::find_sgx_extension_octet` をそのまま再利用する。TDX 固有なのは **TD Quote のバイナリ構造から PCK チェーンを取り出す部分だけ**（`provision/tdx/tdx_provision.cpp`）。

差分は 2 点:

1. **signature_data の開始オフセットが version で変わる**
   - v4: `Header(48) | TD report body(584 固定) | sig_len(u32) | sig_data`（`report_base = 48`）
   - v5: `Header(48) | body_type(u16) | body_size(u32) | body | sig_len(u32) | sig_data`（`report_base = 54`、+6 バイトの body descriptor）
   - v5 は body 長が明示されるためそれを読む。TD report 1.5（648B）は v5 で `body_type=3` として運ばれ、v4 には現れない（Humane-RAFW-TDX も v4 を `report_base=48` 固定で扱う）。
2. **PCK チェーンが二重ネスト**: `sig_data = sig(64) | attest_pub_key(64) | cert_data{ type=6 (QE_REPORT_CERTIFICATION_DATA): qe_report(384) | qe_report_sig(64) | qe_auth_data | cert_data{ type=5 (PCK_CERT_CHAIN): PCK PEM チェーン } }`。SGX(v3) は type=5 が `sig_data` 直下にあるのに対し、TDX は外側 type=6 の中に内側 type=5 が入る。

パーサは外側 type=6 本体の終端が `sig_data` 終端と一致し、内側 type=5 本体もそこで閉じる、という**自己整合性**を要求する（GCP の TD Quote は固定長 8000B バッファで末尾がゼロ埋めのため、ファイル長ではなく宣言サイズでパースする）。`tee_type != 0x81` の Quote（SGX 等）は明示的に拒否する。

> 実機検証: GCP Confidential VM (TDX) が返す v4 Quote で provision を end-to-end 確認済み（PPID 16B 抽出 → ChipIdBinding `teeType=tdx(1)` 発行）。v5 は仕様（report_base=54 + 同一 sig_data 構造）に基づく実装で、構造の自己整合性チェックで保護している。

### AMD SEV-SNP（実装済 / provision のみ）

SGX/TDX と異なり、**Chip ID が attestation 本体（署名対象）に含まれる**ため、証明書ではなく Report から抽出する。

- **抽出元 = Attestation Report の `CHIP_ID` フィールド（オフセット `0x1A0`、64 バイト）**。
  - このオフセットは AMD SEV-SNP Firmware ABI Spec (Rev 1.58) の Table 23 で定義され、Report VERSION 2〜5 で**不変**（v3 で CPUID 3 バイト、v5 で MIT vector が追加されたが、いずれも旧 Reserved 領域の消費であり既存フィールドは移動していない）。署名対象 `0x0–0x29F` / SIGNATURE `0x2A0–0x49F` / 全長 1184B も固定。
  - 実装は VERSION が既知範囲（2〜5）であることを確認し、未知の上位バージョンは安全側に倒して拒否する（SGX で cert_key_type==5 を要求するのと同じ防御線）。
- VCEK Cert にも同値が `HWID` extension（OID `1.3.6.1.4.1.3704.1.4`）として載っているため、抽出した CHIP_ID と VCEK hwID を**ダメ押しでクロスチェック**する（必須ではないが両ソースの一致を明示）。
- **`MaskChipId=1` のプラットフォームでは CHIP_ID が 0 埋め**される。この場合 chip 固有でない値を bind してしまい binding が無意味になるため、all-zero を検知したら**エラーで停止**する（SGX の暗号化 PPID は警告のみだが、SNP の masked CHIP_ID はより明確に危険なため停止）。

#### ベンダー検証（インプロセス自前実装）

VCEK チェーン検証（ARK→ASK→VCEK）と Report 署名検証（VCEK が `0x0–0x29F` に ECDSA-P384/SHA-384 で署名）は、SGX の PCK チェーン検証や CCA の ES384 検証と同じく **OpenSSL でインプロセス実装**する（`provision/sev-snp/snp_provision.cpp`）。外部ツール snpguest への subprocess 依存は持たない。

- **信頼根（AMD ARK）の pin**: `provision/sev-snp/amd_ark_pubkeys.hpp` にハードコードした各世代 ARK の公開鍵 SHA-384（Milan/Genoa/Turin、AMD KDS の `cert_chain` から取得）と、入力 `ark.pem` の SubjectPublicKeyInfo の SHA-384 を照合する。一致した ARK のみを信頼アンカーとして採用する。これで SGX の Intel root ハードコードと同じ「信頼根はコードが握る」プロパティを保つ（ARK は RSA-4096 で生鍵が嵩むため、SGX の P-256 生 EC point 比較とは異なりダイジェストを pin する）。
- **チェーン検証**: pin した ARK を `X509_STORE` の信頼アンカーに据え、ASK を untrusted 中間として VCEK を `X509_verify_cert` で検証する（SGX の `verify_pck_chain` と同じフロー。AMD の ARK/ASK は RSA-PSS 署名だが OpenSSL 3.x がそのまま検証する）。
- **Report 署名検証**: VCEK 公開鍵（EC P-384）で `report[0x0, 0x2A0)` の ECDSA-P384/SHA-384 署名を検証する。SIGNATURE フィールド（`0x2A0`）の R / S はそれぞれ 72 バイト幅のリトルエンディアン整数なので、ビッグエンディアンに反転して `ECDSA_SIG` を組み立て、DER 化して `EVP_DigestVerify` に渡す（CCA の raw r‖s → DER → `EVP_DigestVerify` と同型）。
- provision の検証フロー: **Report ヘッダ検証 → ARK pin 照合 → ARK→ASK→VCEK チェーン検証 → VCEK による Report 署名検証 → 通過後に CHIP_ID 抽出**。

> 注: endorsement の Subject Public Key には SGX の PCK leaf と対称に **VCEK leaf の公開鍵**を流用する。verify サブコマンドも同じ検証経路（`verify_and_extract`）を再利用する。

### Arm CCA（実装済 / provision のみ）

CCA には **X.509 が一切無い**。証拠は CBOR/COSE 形式の CCA Attestation Token で、Chip ID は SNP と同様に **token 本体（署名対象）に含まれる**。

- **抽出元 = CCA Platform Token の `cca-platform-instance-id`（EAT claim 256, UEID）**。先頭 1 バイトが UEID type（`0x01`=RAND）、続いて 32 バイトの個体一意識別子（計 33B）。Platform Attestation Key (CPAK) の一意識別子であり、SGX の PPID / SNP の CHIP_ID に対応する「個体シリアル相当」。
  - `cca-platform-implementation-id`（claim 2396）は**実装クラス共通値**（製品モデル相当）で、proxy 検出には使えないため Chip ID には採らない（SGX で FMSPC でなく PPID を選んだのと同じ判断）。
- **token 構造**: 最上位は CBOR tag 399（RATS CCA token v01, EAT collection）の map で、`cca-platform-token`（key 44234）と `cca-realm-delegated-token`（key 44241）を持つ。各 token は COSE_Sign1（CBOR tag 18）。Platform Token は **CPAK が ES384（ECDSA P-384/SHA-384）で署名**。Platform と Realm は「Platform の `cca-platform-challenge` = Realm 公開鍵(RAK)のハッシュ」で結合される（Delegated Model）。

#### ベンダー検証 = CPAK pin（`provision/cca/cca_cpak_pubkey.hpp`）

CCA に証明書チェーンは無いため、SGX の Intel root pubkey / SNP の ARK と同様に **CPAK 公開鍵をコードに pin** し、Platform Token の COSE_Sign1 署名を OpenSSL（ES384）で直接検証する。

- 検証フロー: **CPAK pin で COSE_Sign1(Platform Token) の署名検証 → 通過後に instance-id 抽出**。CBOR/COSE は新規ビルド依存を避けるため `common/cbor.hpp` の最小実装で扱う（この token 形状に必要な範囲のみ。Sig_structure を再構築し ECDSA 検証は OpenSSL）。
- pin する CPAK は QEMU フルエミュレーション環境の **dev 鍵**：TF-A の `qemu_plat_attest_token.c` にハードコードされた静的 Platform Token（TF-M iat-verifier の `cca_example_platform_token.yaml`）を署名した鍵で、出どころは TF-M `iat-verifier/tests/data/cca_platform.pem`。veraison/ccatoken の testRMMCPAK と一致し、実機取得 token の署名からの ECDSA 公開鍵復元とも bit 一致を確認済み。
- 実機 CCA では CPAK は CoRIM 等の endorsement で配布されるため、本 pin は **PoC（QEMU）専用**。realm token / platform↔realm binding の検証は instance-id 抽出には不要なので provision では行わない。

> endorsement の Subject Public Key には、SGX の PCK leaf / SNP の VCEK leaf と対称に **CPAK 公開鍵**（= instance-id が指す Platform Attestation Key）を流用する。CCA の verify サブコマンド対応は未実装（現状 provision のみ）。

## X.509 拡張 OID 設計

組織エンドースメント証明書には以下の Critical Extension を含める。

### 暫定 OID 体系

実運用では組織の Private Enterprise Number (PEN) を用いて以下のように振る：

```
1.3.6.1.4.1.<PEN>.1               TEE Anchor namespace
1.3.6.1.4.1.<PEN>.1.1             ChipIdBinding extension (Critical)
1.3.6.1.4.1.<PEN>.1.2             TeeTypeIdentifier extension
1.3.6.1.4.1.<PEN>.1.3             AttestationProfileRef extension
```

開発中は PEN として未割当の `99999` をプレースホルダで使う。

### ChipIdBinding extension の構造

```
ChipIdBinding ::= SEQUENCE {
    teeType        TeeType,
    chipId         OCTET STRING,
    issuedAt       GeneralizedTime,
    notes          UTF8String OPTIONAL
}

TeeType ::= ENUMERATED {
    sgx       (0),
    tdx       (1),
    sevSnp    (2),
    armCca    (3)
}
```

Phase 1 では DER エンコード済みのバイト列を OCTET STRING にそのまま入れ、内部構造のパーサは `src/binding/chip_id.cpp` に置く。

## サブコマンド詳細

### `tee-anchor ca-init`

引数：
- `--out-dir <dir>` (required): 出力先ディレクトリ
- `--subject <DN>`: CA の Subject DN（デフォルト `CN=TEE Anchor Org CA`）
- `--validity-days <N>`: CA の有効期限（デフォルト 3650）
- `--curve <name>`: ECDSA 楕円曲線（デフォルト `P-384`）
- `--force`: 既存ファイル上書き許可

出力：
- `<out-dir>/ca.key`: PEM 形式の秘密鍵（パーミッション 0600）
- `<out-dir>/ca.crt`: PEM 形式の自己署名証明書

### `tee-anchor provision`

共通引数：
- `--report <file>` (required): AR（Attestation Report）。TEE 種別に依らずこの 1 つのオプションで渡す
  - `sgx`: SGX Quote（バイナリ、`quote.dat`）
  - `tdx`: TD Quote（バイナリ、`quote.dat`）
  - `snp`: SNP Attestation Report（バイナリ、`report.bin`）
  - `cca`: CCA Attestation Token（CBOR、`cca-token.cbor`）
- `--ca-key <file>` (required): 組織 CA 秘密鍵
- `--ca-cert <file>` (required): 組織 CA 証明書
- `--out <file>` (required): 出力先（組織エンドースメント証明書、PEM）
- `--subject <DN>`: 発行する証明書の Subject DN（省略時は Chip ID から自動生成）
- `--validity-days <N>`: 有効期限（デフォルト 365）
- `--tee-type <sgx|tdx|snp|cca>`: TEE 種別（デフォルト `sgx`）

SEV-SNP 用引数（`--tee-type snp`）：
- `--certs <dir>` (required): `ark.pem` / `ask.pem` / `vcek.pem` を含むディレクトリ（AMD KDS から取得。チェーン/署名検証はインプロセスで行う）

設計判断（AR の受け渡し）: TEE ごとに AR の呼称は Quote / Report / Token と異なるが、CLI としてはいずれも「AR そのもの」であるため `--report` 1 つに統一する。TEE 種別の切り替えは `--tee-type` のみで表現し、オプション名は変えない。

設計判断（SGX/TDX）: 入力は `quote.dat` 1 つに統一する。Quote の Certification Data に PCK 証明書チェーンが内包されており（SGX: `cert_key_type==5` / TDX: 外側 `type=6` の中の内側 `type=5`）、別途 PCS / PCCS から PCK 証明書を取得する必要がないため。
設計判断（SNP）: SNP の Report には証明書チェーンが含まれないため、KDS から取得した VCEK チェーン（`certs/`）を Report と併せて入力に取る。
設計判断（CCA）: token 自体に Platform/Realm の COSE_Sign1 が含まれるため入力は `cca-token.cbor` 1 つ。信頼根の CPAK は token 外（コードに pin）。

処理（SGX）：
1. Quote をロードしバイナリ構造をパース、Certification Data から PCK 証明書チェーンを抽出
2. PCK チェーンを **ハードコードした Intel SGX Root CA 公開鍵**（QvE 互換、SEC1 uncompressed 65B）に対して検証
3. 検証通過した leaf 証明書の SGX Extensions から PPID(16B) を抽出
4. Subject DN を構築（明示指定があればそれを、なければ `CN=tee-anchor-<ppid-prefix>`）
5. 新規鍵ペアは生成せず、PCK leaf の公開鍵を Subject Public Key として使用
   - 理由: 組織エンドースメントは「この PCK 公開鍵を持つマシン = 組織管理下」を表明するため
6. ChipIdBinding extension（Critical、`chipId = PPID`）を追加
7. 組織 CA 秘密鍵で署名
8. PEM 形式で出力

処理（TDX）：SGX とほぼ同一で、差は 1 のみ。
1. TD Quote をロードし version(v4/v5) に応じて signature_data 位置を決め、二重ネスト（外側 `type=6` → 内側 `type=5`）を辿って PCK 証明書チェーンを抽出（`tee_type != 0x81` は拒否）
2.〜8. SGX と同一（チェーン検証 → PPID 抽出 → endorsement 発行。`teeType = tdx(1)`）

処理（SNP）：
1. Report をロードしヘッダを検証（長さ 1184B、VERSION ∈ 2..5、SIGNATURE_ALGO == ECDSA-P384/SHA-384）
2. `certs/ark.pem` の公開鍵を **ハードコードした AMD ARK 公開鍵 SHA-384**（Milan/Genoa/Turin）と pin 照合し、一致した ARK を信頼アンカーとして採用
3. pin した ARK を信頼根に **`X509_verify_cert` で ARK→ASK→VCEK チェーンを検証**し、続けて **VCEK 公開鍵で Report 署名（`0x0–0x29F` の ECDSA-P384/SHA-384）を `EVP_DigestVerify` で検証**（いずれもインプロセス）
4. 検証通過後に Report の `CHIP_ID`（offset `0x1A0`、64B）を抽出（all-zero なら MaskChipId としてエラー）。VCEK hwID とクロスチェック
5. 新規鍵ペアは生成せず、VCEK leaf の公開鍵を Subject Public Key として使用
6. ChipIdBinding extension（Critical、`teeType = sevSnp(2)`、`chipId = CHIP_ID`）を追加
7. 組織 CA 秘密鍵で署名
8. PEM 形式で出力

処理（CCA）：SNP と同様に Chip ID は token 本体から取り、ベンダー検証は CPAK pin で行う。
1. `cca-token.cbor` をロードし CBOR をパース（最上位 tag 399 の map → `cca-platform-token`(44234) の COSE_Sign1）
2. COSE_Sign1 の alg が ES384(-35) であることを確認し、Sig_structure（`["Signature1", protected, b"", payload]`）を再構築
3. **ハードコードした CPAK 公開鍵**（P-384）で Sig_structure に対する署名を検証（raw r||s → DER 変換のうえ OpenSSL `EVP_DigestVerify`）
4. 検証通過後に payload(claims) から `cca-platform-instance-id`(256, 33B) を抽出
5. 新規鍵ペアは生成せず、CPAK の公開鍵を Subject Public Key として使用
6. ChipIdBinding extension（Critical、`teeType = armCca(3)`、`chipId = instance-id`）を追加
7. 組織 CA 秘密鍵で署名
8. PEM 形式で出力

CRL は本サブコマンドでは確認しない。理由は本ドキュメントの「CRL 設計」節を参照。

### `tee-anchor verify`

provision と同じく AR は `--report` で受け取り（SNP のみ `--certs` が追加で必要）、内部の検証経路が TEE 種別で異なる。検証は「(1) ベンダー証拠検証 + Chip ID 抽出 → (2) 組織 chain 検証(+任意 CRL) → (3) Chip ID bit-for-bit 照合」の 3 段で、(1) だけが TEE 別、(2)(3) は共通。

共通引数：
- `--report <file>` (required): AR（Attestation Report）。provision と同じく TEE 種別に依らずこの 1 つのオプションで渡す
  - `sgx`: SGX Quote（バイナリ、`quote.dat`）
  - `tdx`: TD Quote（バイナリ、`quote.dat`）
  - `snp`: SNP Attestation Report（バイナリ、`report.bin`）
  - `cca`: CCA Attestation Token（CBOR、`cca-token.cbor`）
- `--org-cert <file>` (required): 組織エンドースメント証明書（PEM）
- `--org-ca <file>` (required): 組織 Root CA 証明書（PEM、trust anchor）
- `--crl <file>`: 組織 CRL（PEM、任意。指定時のみ失効チェックを行い、失効なら exit 24）
- `--tee-type <sgx|tdx|snp|cca>`: TEE 種別（デフォルト `sgx`）

SEV-SNP 用引数（`--tee-type snp`）：
- `--certs <dir>` (required): `ark.pem` / `ask.pem` / `vcek.pem` を含むディレクトリ（チェーン/署名検証はインプロセス）

処理（SGX）：
1. Quote をパース、CERT_DATA から PCK Cert チェーンを抽出 → Intel Root CA(ハードコード公開鍵)で検証 → PPID を抽出
2. 組織エンドースメント証明書を組織 CA で検証（ChipIdBinding は Critical のため `X509_V_FLAG_IGNORE_CRITICAL`、`--crl` 指定時は `X509_V_FLAG_CRL_CHECK`）
3. ChipIdBinding の `chipId` と PPID を **bit-for-bit 一致確認**
4. 全成功で exit 0、各失敗ステップに応じた非ゼロ exit code

処理（TDX）：SGX と同一で、差は 1 の Quote パースのみ（v4/v5 フレーミング判定 + 外側 type=6 → 内側 type=5 の降下。`provision/tdx/tdx_provision.cpp` を verify でも再利用）。2.〜4. は SGX と完全共通（exit code も同じ）。

処理（SNP）：
1. Report ヘッダ検証 → ARK pin 照合 → **ARK→ASK→VCEK チェーン検証 + VCEK による Report 署名検証（いずれもインプロセス）** → 通過後に CHIP_ID(0x1A0, 64B) を抽出（provision と同一経路 `verify_and_extract` を再利用）
2. 組織エンドースメント証明書を組織 CA で検証（SGX と共通）
3. ChipIdBinding の `chipId` と CHIP_ID を **bit-for-bit 一致確認**
4. 全成功で exit 0

処理（CCA）：SNP と同様に (1) を provision と同一経路で再利用する。
1. `cca-token.cbor` をパース → CPAK pin で Platform Token(COSE_Sign1/ES384) の署名を検証 → 通過後に instance-id(claim 256, 33B) を抽出（`provision/cca/cca_provision.cpp` の `verify_and_extract` を verify でも再利用）
2. 組織エンドースメント証明書を組織 CA で検証（SGX と共通）
3. ChipIdBinding の `chipId` と instance-id を **bit-for-bit 一致確認**
4. 全成功で exit 0（exit code も他 TEE と共通：CPAK pin/COSE 署名失敗は 20）

> 注: provision と同様、Quote/Report/Token の署名・チェーン検証はベンダー証拠検証の層（SGX: 自前 PCK 検証 or 実運用では QvL / SNP: ARK pin + VCEK チェーン + Report 署名を自前検証 / CCA: CPAK pin で COSE 検証）に閉じ、TEE Anchor のコア責務は組織 endorsement と Chip ID binding の照合にある。SGX 以外（TDX/SNP/CCA）のベンダー検証はすべて OpenSSL でインプロセス実装し、外部ツール依存を持たない。

### Exit Code 設計

```
0   全検証成功
10  引数エラー
20  PCK チェーン検証失敗
21  組織 CA チェーン検証失敗
22  Chip ID 不一致 (← Proxy attack の検出)
23  Quote 署名検証失敗
24  組織 CRL により endorsement が失効済み
30  入出力エラー
40  暗号処理エラー
50  内部エラー
```

## 検証フローの擬似コード

```cpp
int verify(VerifyArgs args) {
    auto quote = load_quote(args.quote_path);
    auto pck_chain = extract_pck_chain(quote);
    auto org_cert = load_pem_cert(args.org_cert_path);
    auto org_ca = load_pem_cert(args.org_ca_path);
    auto intel_root = load_pem_cert(args.intel_root_path);

    // (1) PCK chain verification
    if (!verify_chain(pck_chain, intel_root)) return 20;

    // (2) Org cert chain verification
    if (!verify_chain({org_cert}, org_ca)) return 21;

    // (3) Chip ID binding check
    auto chip_id_from_quote = extract_chip_id_from_pck(pck_chain.leaf());
    auto chip_id_from_org   = extract_chip_id_from_extension(org_cert);
    if (chip_id_from_quote != chip_id_from_org) return 22;

    // (4) Quote signature verification
    if (!verify_quote_signature(quote, pck_chain.leaf().pubkey())) return 23;

    return 0;
}
```

## CRL 設計

CRL を 2 種類に分けて考える。

### Intel 側 CRL（PCK CRL / Intel Root CA CRL）→ TEE Anchor のスコープ外（全フェーズ）

- 失効主体: Intel（PCK Platform/Processor CA、Intel SGX Root CA）
- 検証主体: RP 側で動作する Intel **QvL**（`sgx_qv_verify_quote()` が内部で PCK CRL / Root CA CRL / TCB info を一括チェック）
- TEE Anchor のスタンス: **実装しない**。QvL と完全に重複し、provisioning 段階で実行しても TOCTOU で意味が薄い。Intel chain の運用状態は Intel と RP の関心事で、組織 endorsement が表明する所有関係とは射程が別。
- なお `provision` / `verify` が PCK チェーン署名検証を自前で行うのは、QvL 非依存で動かせる standalone PoC としての性質を保つため。Intel CRL チェックはこの検証経路にも追加しない。

### 組織側 CRL（組織エンドースメント証明書の失効）→ 実装済 (Phase 2.0)

組織管理下マシンが廃棄・盗難・売却された際に、対応する組織エンドースメント証明書を失効させる仕組み。

- 失効主体: 組織（自身が発行した endorsement を自身の CA で失効させる）
- 検証主体: TEE Anchor の `verify`（ここでしか出来ない）
- 主な発火ケース: マシン退役・所有移転・物理攻撃で侵害が疑われる場合（TEE Anchor の脅威モデル直結）
- 標準 X.509 CRL（RFC 5280, v2）を採用、OpenSSL の標準フローに乗る

#### サブコマンド

- `tee-anchor revoke --ca-cert <ca.crt> --cert <endorsement.crt> [--reason <name>] [--db <path>]`
  - 失効対象 endorsement の serial を抽出し、revocation DB に追加するだけ。CRL ファイルは出力しない。
  - reason: RFC 5280 CRLReason 名 (`unspecified` / `keyCompromise` / `cACompromise` / `affiliationChanged` / `superseded` / `cessationOfOperation` / `certificateHold` / `privilegeWithdrawn` / `aACompromise`)。省略可。
  - DB の既定パス: `<dirname(ca-cert)>/revocations.txt`。

- `tee-anchor crl-issue --ca-key --ca-cert --out <crl.pem> [--validity-days N] [--db <path>]`
  - revocation DB から X.509 CRL を組み立て、組織 CA 鍵で署名・PEM 出力。
  - CRL Number は DB 内の連番カウンタを自動でインクリメント。
  - CRL の `nextUpdate` は既定 `now + 7 days`。

- `tee-anchor verify ... --crl <crl.pem>` (任意)
  - `--crl` を渡したときだけ X509_STORE に CRL を投入し `X509_V_FLAG_CRL_CHECK` を有効化。
  - 失効済みの endorsement なら exit code 24 (`X509_V_ERR_CERT_REVOKED`) で返す。
  - `--crl` 未指定なら従来通り CRL チェックは行わない (後方互換)。

#### Revocation DB フォーマット

依存ライブラリを増やさない flat text:

```
# TEE Anchor revocation database (v1)
crl-number 3
<serial-hex> <YYYYMMDDHHMMSSZ> [<reason-name>]
...
```

#### 今後の Phase 2.x 検討

- CRL Distribution Point extension を endorsement 発行時に埋める（RP が CRL 場所を自動取得できるように）
- `removeFromCRL` reason / delta CRL（小規模では不要）
- HSM 連携 (現在は CA key を平文 PEM で保持)

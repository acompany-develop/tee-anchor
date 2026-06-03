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

### AMD SEV-SNP

- VCEK Cert の Subject に `HWID` extension（OID `1.3.6.1.4.1.3704.1.4`）として 64 バイトの CHIP_ID
- Attestation Report の `CHIP_ID` フィールドにも同値が含まれる
- 両者を照合する

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

引数：
- `--quote <file>` (required): 入力する Quote（バイナリ、`quote.dat`）
- `--ca-key <file>` (required): 組織 CA 秘密鍵
- `--ca-cert <file>` (required): 組織 CA 証明書
- `--out <file>` (required): 出力先（組織エンドースメント証明書、PEM）
- `--subject <DN>`: 発行する証明書の Subject DN（省略時は Chip ID から自動生成）
- `--validity-days <N>`: 有効期限（デフォルト 365）
- `--tee-type <sgx|tdx|snp>`: TEE 種別（デフォルト `sgx`、Phase 1 では `sgx` のみ実装）

設計判断: provision / verify とも入力は `quote.dat` 1 つに統一する。Quote の Certification Data（`cert_key_type == 5`）に PCK 証明書チェーンが内包されており、別途 PCS / PCCS から PCK 証明書を取得する必要がないため。

処理：
1. Quote をロードしバイナリ構造をパース、Certification Data から PCK 証明書チェーンを抽出
2. PCK チェーンを **ハードコードした Intel SGX Root CA 公開鍵**（QvE 互換、SEC1 uncompressed 65B）に対して検証
3. 検証通過した leaf 証明書の SGX Extensions から PPID(16B) を抽出
4. Subject DN を構築（明示指定があればそれを、なければ `CN=tee-anchor-<ppid-prefix>`）
5. 新規鍵ペアは生成せず、PCK leaf の公開鍵を Subject Public Key として使用
   - 理由: 組織エンドースメントは「この PCK 公開鍵を持つマシン = 組織管理下」を表明するため
6. ChipIdBinding extension（Critical、`chipId = PPID`）を追加
7. 組織 CA 秘密鍵で署名
8. PEM 形式で出力

CRL は本サブコマンドでは確認しない。理由は本ドキュメントの「CRL 設計」節を参照。

### `tee-anchor verify`

引数：
- `--quote <file>` (required): SGX Quote（バイナリ）
- `--org-cert <file>` (required): 組織エンドースメント証明書（PEM）
- `--org-ca <file>` (required): 組織 Root CA 証明書（PEM）
- `--intel-root <file>`: Intel SGX Root CA 証明書（PEM、デフォルトはバンドル）
- `--json`: 結果を JSON で出力

処理：
1. Quote をパース、CERT_DATA から PCK Cert チェーンを抽出
2. PCK Cert チェーンを Intel Root CA で検証（標準 DCAP 検証フロー）
3. 組織エンドースメント証明書を組織 CA で検証
4. PCK Cert と組織エンドースメント証明書から Chip ID をそれぞれ抽出
5. **bit-for-bit 一致確認**
6. Quote の ECDSA 署名を PCK Cert の公開鍵で検証
7. 全成功で exit 0、各失敗ステップに応じた非ゼロ exit code

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

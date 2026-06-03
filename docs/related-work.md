# Related Work

論文の Related Work セクションのドラフト兼、実装上「どこを真似しないか」の参照資料。

## 比較表

| 研究 | 物理攻撃対策 | TEE 横断 | TPM 不要 | 組織エンドースメント | 末端直接検証 | X.509 ベース | 標準準拠 | 任意組織展開 |
|------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Battering RAM / TEE.fail (脅威) | — | — | — | — | — | — | — | — |
| DCEA (Flashbots) | ✅ | △(TDX 中心) | ❌ | ✅ | ❌ | △ | △ | △ |
| Intel POE | ✅ | ❌(Intel のみ) | ✅ | ✅ | ❌ | ❌(CoRIM) | △ | △ |
| AMD VLEK | △ | ❌(AMD のみ) | ✅ | ✅ | △ | ✅ | △ | ❌ |
| Pontes (SPIRE) | ❌ | △(SNP/TDX) | △ | △ | ❌(scope 外) | ✅ | △ | ✅ |
| Proof of Cloud Alliance | ✅ | △ | ❌ | ✅ | △ | ❌ | ❌ | ❌ |
| Veraison | ❌ | △(CCA/PSA) | ✅ | ✅ | ✅ | ❌(CoRIM) | ✅ | ✅ |
| SVSM-vTPM | △ | ❌(SNP のみ) | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ |
| CNCF Hybrid CA | △ | ✅ | ❌ | ✅ | △ | ✅ | △ | ✅ |
| MAA / Trust Authority | ❌ | △ | △ | ❌ | ❌ | △ | △ | ❌ |
| Automata / ZKP 系 | ❌ | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ | ✅ |
| **TEE Anchor (本研究)** | **✅** | **✅** | **✅** | **✅** | **✅** | **✅** | **✅** | **✅** |

## 主要な既存研究と差別化点

### DCEA (Flashbots)
- TPM + Intel TXT 依存、TDX 中心
- 本研究: TPM 不要、TEE 横断

### Intel POE (2026 年 2 月発表)
- Intel SGX/TDX 限定、CoRIM/CBOR ベース
- 「Platform Endorser」は Intel の認定プロセスに従う必要があるとみられる
- 本研究: ベンダー非依存、X.509 ベースで既存 PKI 統合容易、認定不要で任意組織展開

### AMD VLEK
- AMD と enrolled CSP（事実上 AWS）の閉じた関係に限定
- 本研究: 任意組織が独立展開可能

### Proof of Cloud Alliance (2025 年 11 月発足)
- Web3 コミュニティ前提、集合的 multi-sig レジストリへの信頼が必要
- Level 1 は物理 inspection 必須でスケールしない
- 独自プロトコル
- 本研究: 分散 PKI、X.509 標準準拠、任意業界（金融/防衛/研究機関等）に展開可能

### Veraison
- CoRIM/CBOR 中心で X.509 エコシステム統合に追加レイヤー必要
- 主に CCA/PSA 対応、SGX/TDX/SEV-SNP 対応は限定的
- 本研究: X.509 ネイティブ、主要クラウド TEE 対応、Veraison との相互運用も設計レベルで可能

### SVSM-vTPM (Narayanan et al., ACSAC 2023)
- vTPM 実装が前提、SEV-SNP 限定
- 本研究: TPM 不要、TEE 横断

### CNCF Hybrid CA (JD.com, 2025)
- 物理 TPM 必須、TPM ベンダー依存が残る
- 本研究: TPM 不要、CPU 側 Chip ID 直接利用

### MAA / Intel Trust Authority / GCA
- 中央集権 Verifier への信頼前提、ベンダー/クラウドロックイン
- 本研究: 中央集権 Verifier 不要、組織独自展開可能、オフライン検証可

### SPIRE / Pontes
- workload identity 発行が目的、物理攻撃対策はスコープ外
- 本研究は SPIRE プラグインとして統合可能（Discussion 章で言及予定）

### Automata / ZKP 系
- zkVM ベースで重い暗号処理、物理攻撃を防げない
- 本研究: 軽量、物理攻撃を明示的脅威に

### Bellemare 2024
- PUF/masking/open source hardware による長期ビジョン論文、実装なし
- 本研究: 既存 TEE に即時適用可能

## 論文での書き方方針

- Related Work 各項目は 1〜2 段落で紹介
- 各項目の末尾で「However, ...」で本研究との差別化を明示
- 上記比較表を 1 枚挿入
- Introduction では制約（TPM 依存、ベンダー依存、Verifier 集権、Web3 特化等）を箇条書きにし「全部解消する設計が必要」と主張
- Discussion で各既存研究との補完関係を議論（DCEA をモード 1、本研究をモード 2 等）

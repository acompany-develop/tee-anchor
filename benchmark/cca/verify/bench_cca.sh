#!/usr/bin/env bash
# bench_cca.sh — Arm CCA 版。「従来 RA 検証器 (evcli)」と「tee-anchor verify」を
# hyperfine でプロセスレベル A/B 計測する。bench_snp.sh の CCA 版。
#
# 計測対象:
#   A. evcli cca check               : CCA トークンの構文 + COSE(ES384) 署名検証
#                                      (SNP の snpguest verify に相当する「従来 RA 検証器」)
#   B. tee-anchor verify --tee-type cca : CPAK pin で COSE 検証 + 組織 endorsement
#                                      chain + instance-id (Chip ID) 照合
#
# ★ 解釈上の注意 (A/B は別実装の独立検証器):
#   tee-anchor は evcli を呼ばず、CBOR/COSE 検証を C++/OpenSSL で自前実装している。
#   よって A(evcli, Go) と B(tee-anchor, C++) は別言語・別実装の独立な検証器であり、
#       B - A を「TEE Anchor 固有オーバーヘッド」と解釈してはいけない。
#   本ベンチは「従来 RA 検証器 vs TEE Anchor 検証器」の総実行時間比較であり、
#   evcli(Go) のランタイム起動コストが交絡する点を論文に明記すること。
#   (SNP も同様: 以前は tee-anchor が snpguest を内部 fork/exec する入れ子だったが、
#    現在は自前実装に置き換えたため、CCA と同じく A=従来ツール / C=自前実装の独立比較になった。)
#   固有オーバーヘッドが要るなら tee-anchor 内部に区間計測 (clock_gettime) を入れる。
#
# 分解能/方法論は bench_snp.sh と同じ (時計より反復回数が効く。-N で sh -c を外す)。
#
# 入力 (BUNDLE_DIR 既定 ~/cca_verify_bundle):
#   cca-token.cbor       … CCA マシン (Realm) から持参する唯一の HW 由来証拠
#   cpak.jwk             … evcli 用 CPAK 公開鍵 (pin 済み dev 鍵から生成済み)
#   cca_endorsement.crt  … tee-anchor provision --tee-type cca で発行 (org 側)
#   ca.crt               … ca-init で生成 (org 側)。ca.key は置かないこと
#
# 使い方:
#   ./bench_cca.sh
#   BUNDLE_DIR=/path ./bench_cca.sh
#   RUNS=100 WARMUP=10 ./bench_cca.sh
#   EVCLI=/path/to/evcli TEE_ANCHOR=/path/to/tee-anchor ./bench_cca.sh

set -euo pipefail

# ---------------------------------------------------------------------------
# 設定 (環境変数で上書き可)
# ---------------------------------------------------------------------------
BUNDLE_DIR="${BUNDLE_DIR:-$HOME/cca_verify_bundle}"
TOKEN="${TOKEN:-$BUNDLE_DIR/cca-token.cbor}"
CPAK_JWK="${CPAK_JWK:-$BUNDLE_DIR/cpak.jwk}"
ORG_CERT="${ORG_CERT:-$BUNDLE_DIR/cca_endorsement.crt}"
ORG_CA="${ORG_CA:-$BUNDLE_DIR/ca.crt}"

WARMUP="${WARMUP:-5}"
RUNS="${RUNS:-50}"
OUT_PREFIX="${OUT_PREFIX:-bench_cca}"

log()  { echo -e "\033[1;32m[bench-cca]\033[0m $*"; }
warn() { echo -e "\033[1;33m[bench-cca]\033[0m $*" >&2; }
die()  { echo -e "\033[1;31m[bench-cca]\033[0m $*" >&2; exit 1; }

command -v hyperfine >/dev/null 2>&1 || die "hyperfine が見つかりません。'sudo apt-get install hyperfine' を実行してください。"

# ---------------------------------------------------------------------------
# evcli / tee-anchor の探索 (bench_snp.sh と同じ流儀)
# ---------------------------------------------------------------------------
find_bin() {
    local explicit="$1"; local on_path="$2"; shift 2
    if [ -n "$explicit" ]; then
        [ -x "$explicit" ] && { echo "$explicit"; return 0; }
        echo ""; return 1
    fi
    if command -v "$on_path" >/dev/null 2>&1; then
        command -v "$on_path"; return 0
    fi
    local c
    for c in "$@"; do
        [ -x "$c" ] && { echo "$c"; return 0; }
    done
    echo ""; return 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

EVCLI="$(find_bin "${EVCLI:-}" evcli \
    "$HOME/go/bin/evcli")" || true
[ -n "$EVCLI" ] || die "evcli が見つかりません。EVCLI=<path> で指定するか 'go install github.com/veraison/evcli@latest' してください。"

TEE_ANCHOR="$(find_bin "${TEE_ANCHOR:-}" tee-anchor \
    "$SCRIPT_DIR/../../tee-anchor" \
    "$HOME/Develop/tee-anchor/tee-anchor")" || true
[ -n "$TEE_ANCHOR" ] || die "tee-anchor が見つかりません。TEE_ANCHOR=<path> で指定するか PATH を通してください。"

# ---------------------------------------------------------------------------
# 入力ファイルの存在確認
# ---------------------------------------------------------------------------
[ -f "$TOKEN" ]    || die "CCA トークンがありません: $TOKEN  (CCA マシンから cca-token.cbor を持参してください)"
[ -f "$CPAK_JWK" ] || die "CPAK JWK がありません: $CPAK_JWK"
[ -f "$ORG_CERT" ] || die "組織 endorsement 証明書がありません: $ORG_CERT  (tee-anchor provision --tee-type cca で発行)"
[ -f "$ORG_CA" ]   || die "組織 CA 証明書がありません: $ORG_CA"

# -N (whitespace split) のためパスに空白不可。
CLAIMS_OUT="$BUNDLE_DIR/.bench_claims.json"   # evcli のクレーム出力先 (測定ノイズを stdout に出さない)
for p in "$EVCLI" "$TEE_ANCHOR" "$TOKEN" "$CPAK_JWK" "$ORG_CERT" "$ORG_CA" "$CLAIMS_OUT"; do
    case "$p" in
        *" "*) die "パスに空白が含まれています: '$p' (-N モードでは不可)";;
    esac
done

log "evcli      : $EVCLI ($("$EVCLI" --version 2>/dev/null | head -1))"
log "tee-anchor : $TEE_ANCHOR"
log "warmup=$WARMUP runs=$RUNS  out=${OUT_PREFIX}.{md,json}"
echo

# ---------------------------------------------------------------------------
# 事前サニティ: 各コマンドが exit 0 で通ることを確認 (失敗を測ると無意味)
# ---------------------------------------------------------------------------
log "sanity: evcli cca check"
"$EVCLI" cca check -t "$TOKEN" -k "$CPAK_JWK" -c "$CLAIMS_OUT" \
    || die "evcli cca check が失敗しました。token/CPAK の整合を確認してください。"
log "sanity: tee-anchor verify --tee-type cca"
"$TEE_ANCHOR" verify --tee-type cca --report "$TOKEN" --org-cert "$ORG_CERT" --org-ca "$ORG_CA" \
    || die "tee-anchor verify (cca) が失敗しました。endorsement/CA の整合を確認してください。"
echo

# ---------------------------------------------------------------------------
# hyperfine 本体
# ---------------------------------------------------------------------------
hyperfine -N \
    --warmup "$WARMUP" \
    --min-runs "$RUNS" \
    --command-name "A. evcli cca check (conventional RA)" \
        "$EVCLI cca check -t $TOKEN -k $CPAK_JWK -c $CLAIMS_OUT" \
    --command-name "B. tee-anchor verify (cca)" \
        "$TEE_ANCHOR verify --tee-type cca --report $TOKEN --org-cert $ORG_CERT --org-ca $ORG_CA" \
    --export-markdown "${OUT_PREFIX}.md" \
    --export-json "${OUT_PREFIX}.json"

echo
log "結果を ${OUT_PREFIX}.md / ${OUT_PREFIX}.json に保存しました。"
warn "注意: B - A は固有オーバーヘッドではない (evcli=Go と tee-anchor=C++ の独立実装比較)。"

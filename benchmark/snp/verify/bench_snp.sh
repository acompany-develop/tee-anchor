#!/usr/bin/env bash
# bench_snp.sh — verify_snp.sh の「snpguest を叩く段」と「tee-anchor verify 段」を
# hyperfine でプロセスレベル A/B 計測する。
#
# 計測対象 (それぞれ独立コマンドとして測る):
#   A. snpguest verify certs        : ARK->ASK->VCEK チェーン検証
#   B. snpguest verify attestation  : VCEK による Report 署名検証
#   C. tee-anchor verify --tee-type snp : 組織 endorsement chain + Chip ID 照合
#
# 注意 (内訳の解釈):
#   C は内部で snpguest をサブプロセスとして起動する。つまり
#       C ≈ (A + B) + 組織 endorsement chain + Chip ID 照合
#   なので「TEE Anchor 固有のオーバーヘッド」は概ね  C - (A + B)  に相当する。
#
# 分解能について:
#   - 時計の分解能はボトルネックではない。支配項はプロセス起動のばらつき。
#   - hyperfine が warmup + 多数回反復 + 統計 (mean±σ, min/max, 外れ値検出) を行う。
#   - -N (--shell=none) で各測定から sh -c のラップを外し、計測オーバーヘッドを最小化する。
#     (副作用: コマンドは空白で分割されるため、パスに空白を含められない。既定パスは安全。)
#
# 使い方:
#   ./bench_snp.sh
#   BUNDLE_DIR=/path/to/bundle ./bench_snp.sh
#   RUNS=100 WARMUP=10 ./bench_snp.sh
#   SNPGUEST=/path/to/snpguest TEE_ANCHOR=/path/to/tee-anchor ./bench_snp.sh

set -euo pipefail

# ---------------------------------------------------------------------------
# 設定 (環境変数で上書き可) — verify_snp.sh と同じ
# ---------------------------------------------------------------------------
BUNDLE_DIR="${BUNDLE_DIR:-$HOME/snp_verify_bundle}"
REPORT="${REPORT:-$BUNDLE_DIR/report.bin}"
CERTS_DIR="${CERTS_DIR:-$BUNDLE_DIR/certs}"
ORG_CERT="${ORG_CERT:-$BUNDLE_DIR/snp_endorsement.crt}"
ORG_CA="${ORG_CA:-$BUNDLE_DIR/ca.crt}"

WARMUP="${WARMUP:-5}"        # ウォームアップ回数 (ページキャッシュ等を温める)
RUNS="${RUNS:-50}"          # 最小反復回数 (軽量ワークロードなので多めに)
OUT_PREFIX="${OUT_PREFIX:-bench_snp}"  # 結果ファイルの接頭辞

log()  { echo -e "\033[1;32m[bench-snp]\033[0m $*"; }
warn() { echo -e "\033[1;33m[bench-snp]\033[0m $*" >&2; }
die()  { echo -e "\033[1;31m[bench-snp]\033[0m $*" >&2; exit 1; }

command -v hyperfine >/dev/null 2>&1 || die "hyperfine が見つかりません。'sudo apt-get install hyperfine' を実行してください。"

# ---------------------------------------------------------------------------
# snpguest / tee-anchor の探索 (verify_snp.sh と同じ)
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

# 代入の置換が非ゼロ終了しても set -e で即死しないよう || true で握る。
SNPGUEST="$(find_bin "${SNPGUEST:-}" snpguest \
    "$HOME/snpguest/target/release/snpguest")" || true
[ -n "$SNPGUEST" ] || die "snpguest が見つかりません。SNPGUEST=<path> で指定するか PATH を通してください。"

TEE_ANCHOR="$(find_bin "${TEE_ANCHOR:-}" tee-anchor \
    "$SCRIPT_DIR/tee-anchor" \
    "$HOME/Develop/tee-anchor/tee-anchor")" || true
[ -n "$TEE_ANCHOR" ] || die "tee-anchor が見つかりません。TEE_ANCHOR=<path> で指定するか PATH を通してください。"

# ---------------------------------------------------------------------------
# 入力ファイルの存在確認 (verify_snp.sh と同じ)
# ---------------------------------------------------------------------------
[ -f "$REPORT" ]    || die "Report がありません: $REPORT"
[ -d "$CERTS_DIR" ] || die "certs ディレクトリがありません: $CERTS_DIR"
for f in ark.pem ask.pem vcek.pem; do
    [ -f "$CERTS_DIR/$f" ] || die "証明書がありません: $CERTS_DIR/$f"
done
[ -f "$ORG_CERT" ]  || die "組織 endorsement 証明書がありません: $ORG_CERT"
[ -f "$ORG_CA" ]    || die "組織 CA 証明書がありません: $ORG_CA"

# パスに空白が含まれると -N (whitespace split) で壊れるため事前に弾く。
for p in "$SNPGUEST" "$TEE_ANCHOR" "$REPORT" "$CERTS_DIR" "$ORG_CERT" "$ORG_CA"; do
    case "$p" in
        *" "*) die "パスに空白が含まれています: '$p' (-N モードでは不可。空白なしのパスに置いてください)";;
    esac
done

log "snpguest   : $SNPGUEST"
log "tee-anchor : $TEE_ANCHOR"
log "warmup=$WARMUP runs=$RUNS  out=${OUT_PREFIX}.{md,json}"
echo

# ---------------------------------------------------------------------------
# hyperfine 本体
#   -N            : shell ラップ無し (計測オーバーヘッド最小化)
#   --warmup      : 最初の数回は捨ててキャッシュを温める
#   --min-runs    : 軽量なので多めに回して σ を下げる
#   --command-name: 表示名
#   --export-*    : 後段の集計 / 論文表用に md と json を吐く
# ---------------------------------------------------------------------------
hyperfine -N \
    --warmup "$WARMUP" \
    --min-runs "$RUNS" \
    --command-name "A. snpguest verify certs" \
        "$SNPGUEST verify certs $CERTS_DIR" \
    --command-name "B. snpguest verify attestation" \
        "$SNPGUEST verify attestation $CERTS_DIR $REPORT" \
    --command-name "C. tee-anchor verify (snp)" \
        "$TEE_ANCHOR verify --tee-type snp --report $REPORT --certs $CERTS_DIR --snpguest $SNPGUEST --org-cert $ORG_CERT --org-ca $ORG_CA" \
    --export-markdown "${OUT_PREFIX}.md" \
    --export-json "${OUT_PREFIX}.json"

echo
log "結果を ${OUT_PREFIX}.md / ${OUT_PREFIX}.json に保存しました。"
log "TEE Anchor 固有オーバーヘッド ≈ C - (A + B) として解釈してください。"

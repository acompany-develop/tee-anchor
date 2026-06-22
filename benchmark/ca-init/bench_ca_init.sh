#!/usr/bin/env bash
# bench_ca_init.sh — `tee-anchor ca-init`（組織 Root CA 発行）のプロセスレベル計測。
#
# 計測対象 (EC 曲線ごとに独立コマンドとして測る。鍵生成コストが曲線で変わるため):
#   A. ca-init P-256
#   B. ca-init P-384   (tee-anchor の既定。論文の基準値はこれ)
#   C. ca-init P-521
#
# 注意:
#   - ca-init は **TEE 非依存** のコマンド（P-384 鍵生成 + 自己署名 Cert）。
#     SGX/TDX/SNP/CCA いずれでも同一処理なので、本スクリプトは sgx/ 配下に置いて
#     あるが内容は TEE に依存しない（プロビジョニング側の共通コスト計測）。
#   - 支配項は鍵生成 (ECDSA keygen) とプロセス起動のばらつき。
#   - **既存ファイルの影響排除**: ca-init は --force で既存 ca.key/ca.crt を上書き
#     できるが、(1) 上書き経路は本来の「空ディレクトリへの新規発行」とコードパスが
#     異なり得る、(2) 既存ファイル状態が計測を歪め得る。そこで本スクリプトは
#     **各試行の直前（計測区間の外）で ca.key/ca.crt を削除**し、毎回まっさらな
#     状態からの新規発行コストを測る（--force は付けない）。hyperfine では
#     --prepare、bash フォールバックでは各反復前の rm -f で実現する。
#   - hyperfine があればそれを使う（warmup + 多数反復 + 統計 + 外れ値検出）。
#     無ければ bash の簡易ループ計測にフォールバックする。
#
# 使い方:
#   ./bench_ca_init.sh
#   RUNS=200 WARMUP=20 ./bench_ca_init.sh
#   TEE_ANCHOR=/path/to/tee-anchor ./bench_ca_init.sh

set -euo pipefail

WARMUP="${WARMUP:-20}"                       # ウォームアップ回数
RUNS="${RUNS:-200}"                          # 最小反復回数 (軽量なので多めに)
OUT_PREFIX="${OUT_PREFIX:-bench_ca_init}"    # 結果ファイル接頭辞

log()  { echo -e "\033[1;32m[bench-ca-init]\033[0m $*"; }
warn() { echo -e "\033[1;33m[bench-ca-init]\033[0m $*" >&2; }
die()  { echo -e "\033[1;31m[bench-ca-init]\033[0m $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# tee-anchor の探索 (bench_snp.sh と同じ流儀)
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

TEE_ANCHOR="$(find_bin "${TEE_ANCHOR:-}" tee-anchor \
    "$SCRIPT_DIR/../../tee-anchor" \
    "$HOME/Develop/tee-anchor/tee-anchor")" || true
[ -n "$TEE_ANCHOR" ] || die "tee-anchor が見つかりません。TEE_ANCHOR=<path> で指定するか PATH を通してください。"

# 計測用の作業ディレクトリ (ca.key / ca.crt の出力先。--force で毎回上書き)
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

log "tee-anchor : $TEE_ANCHOR"
log "work dir   : $WORK"
log "warmup=$WARMUP runs=$RUNS  out=${OUT_PREFIX}.{md,json}"
echo

# 各試行直前に出力物を消すための prepare（計測区間の外で実行する）
PREP_RM="rm -f $WORK/ca.key $WORK/ca.crt"

# 健全性チェック: 既定の P-384 が 1 回成功するか（クリーンな状態から）
$PREP_RM
"$TEE_ANCHOR" ca-init --out-dir "$WORK" --curve P-384 >/dev/null 2>&1 \
    || die "ca-init が失敗しました。バイナリ/権限を確認してください。"

# ===========================================================================
# 計測本体
# ===========================================================================
if command -v hyperfine >/dev/null 2>&1; then
    log "hyperfine を使用します。"
    # パスに空白が含まれると -N (whitespace split) で壊れるため事前に弾く。
    for p in "$TEE_ANCHOR" "$WORK"; do
        case "$p" in *" "*) die "パスに空白が含まれています: '$p' (-N モードでは不可)";; esac
    done
    # --prepare: 各試行の直前（計測区間の外）で既存の ca.key/ca.crt を削除し、
    #            毎回まっさらな状態からの新規発行コストを測る（--force は付けない）。
    hyperfine -N \
        --warmup "$WARMUP" \
        --min-runs "$RUNS" \
        --prepare "$PREP_RM" \
        --command-name "A. ca-init P-256" \
            "$TEE_ANCHOR ca-init --out-dir $WORK --curve P-256" \
        --command-name "B. ca-init P-384 (default)" \
            "$TEE_ANCHOR ca-init --out-dir $WORK --curve P-384" \
        --command-name "C. ca-init P-521" \
            "$TEE_ANCHOR ca-init --out-dir $WORK --curve P-521" \
        --export-markdown "${OUT_PREFIX}.md" \
        --export-json "${OUT_PREFIX}.json"
    echo
    log "結果を ${OUT_PREFIX}.md / ${OUT_PREFIX}.json に保存しました。"
else
    warn "hyperfine が無いため bash 簡易計測にフォールバックします。"
    warn "より厳密な計測には 'sudo apt-get install hyperfine' を推奨します。"
    echo

    # bash フォールバック: 各コマンドを warmup 後に RUNS 回計測し統計を出す。
    # 各反復の直前（計測区間の外）で $PREP_RM を実行し、既存ファイルの影響を排除する。
    bench_one() {  # $1=表示名  $2..=実行コマンド
        local name="$1"; shift
        local i t0 t1
        for ((i=0; i<WARMUP; i++)); do $PREP_RM; "$@" >/dev/null 2>&1 || true; done
        local ns=()
        for ((i=0; i<RUNS; i++)); do
            $PREP_RM                      # 計測区間の外でクリーンアップ
            t0=$(date +%s%N); "$@" >/dev/null 2>&1 || true; t1=$(date +%s%N)
            ns+=( $((t1 - t0)) )
        done
        printf '%s\n' "${ns[@]}" | awk -v name="$name" -v runs="$RUNS" '
            { v=$1/1e6; a[NR]=v; s+=v; if(NR==1||v<mn)mn=v; if(NR==1||v>mx)mx=v }
            END{
                mean=s/NR;
                for(i=1;i<=NR;i++){d=a[i]-mean; var+=d*d}
                sd=(NR>1)?sqrt(var/NR):0;
                n=asort(a);
                med=(n%2)?a[int(n/2)+1]:(a[n/2]+a[n/2+1])/2;
                printf "%-26s mean %7.3f +/- %6.3f ms  (min %7.3f, median %7.3f, max %7.3f, n=%d)\n",
                       name, mean, sd, mn, med, mx, runs;
                printf "%s\t%.6f\t%.6f\t%.6f\t%.6f\t%.6f\n", name, mean, sd, mn, med, mx >> "/tmp/.bench_ca_init_rows"
            }'
    }
    : > /tmp/.bench_ca_init_rows
    bench_one "A. ca-init P-256"          "$TEE_ANCHOR" ca-init --out-dir "$WORK" --curve P-256
    bench_one "B. ca-init P-384 (default)" "$TEE_ANCHOR" ca-init --out-dir "$WORK" --curve P-384
    bench_one "C. ca-init P-521"          "$TEE_ANCHOR" ca-init --out-dir "$WORK" --curve P-521

    # 簡易 JSON 出力
    awk -F'\t' -v runs="$RUNS" -v warmup="$WARMUP" '
        BEGIN{print "{"; print "  \"tool\": \"bash-fallback\","; print "  \"runs\": " runs ", \"warmup\": " warmup ","; print "  \"results\": ["}
        { if(NR>1) print "    ,"; printf "    {\"name\": \"%s\", \"mean_ms\": %s, \"stdev_ms\": %s, \"min_ms\": %s, \"median_ms\": %s, \"max_ms\": %s}\n",$1,$2,$3,$4,$5,$6 }
        END{print "  ]"; print "}"}' /tmp/.bench_ca_init_rows > "${OUT_PREFIX}.json"
    rm -f /tmp/.bench_ca_init_rows
    echo
    log "結果を ${OUT_PREFIX}.json に保存しました。"
fi

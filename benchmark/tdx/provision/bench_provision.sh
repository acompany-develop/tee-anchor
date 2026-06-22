#!/usr/bin/env bash
# bench_provision.sh — `tee-anchor provision --tee-type tdx`（組織エンドースメント
# 証明書の発行）のプロセスレベル計測。SGX 版 (benchmark/sgx/provision) の TDX 版。
#
# 計測対象:
#   tee-anchor provision --tee-type tdx --quote <quote> \
#       --ca-key <ca.key> --ca-cert <ca.crt> --out <endorsement.crt>
#
# 内訳 (支配項):
#   TD Quote のパース → CERT_DATA(type-6→type-5 入れ子) から PCK 証明書チェーン抽出
#   → SGX 拡張から Chip ID(PPID) 抽出 → 組織 CA 鍵で X.509 エンドースメント証明書を
#   署名・書出。ネットワーク往復は無し（PCK は Quote 内蔵分のみ使用）。
#   ※ provision の処理は SGX とほぼ共通で、TD Quote の framing 差(v4/v5)を吸収する点
#     のみ異なる。フェアな TEE 横断比較のため SGX 版と同条件 (warmup/runs) で測る。
#
# 既存ファイルの影響排除:
#   provision は出力 (--out) のエンドースメント証明書を毎回書き出す。ca-init と同様、
#   既存ファイル状態が計測を歪めないよう **各試行の直前（計測区間の外）で --out を
#   削除**してから測る（hyperfine は --prepare、bash フォールバックは反復前の rm -f）。
#   署名に使う CA (ca.key/ca.crt) はスクリプト先頭で 1 度だけ ca-init して用意する
#   （CA 生成コストは provision の計測には含めない）。
#
# 計測ツール:
#   hyperfine があればそれを使う。無ければ bash 簡易ループにフォールバック。
#
# 使い方:
#   ./bench_provision.sh
#   QUOTE=/path/to/td_quote.dat ./bench_provision.sh
#   BUNDLE_DIR=/path/to/dir ./bench_provision.sh         # $BUNDLE_DIR/quote.dat を使う
#   RUNS=200 WARMUP=20 ./bench_provision.sh
#   TEE_ANCHOR=/path/to/tee-anchor ./bench_provision.sh

set -euo pipefail

WARMUP="${WARMUP:-20}"
RUNS="${RUNS:-200}"
OUT_PREFIX="${OUT_PREFIX:-bench_provision}"
CA_CURVE="${CA_CURVE:-P-384}"          # 署名 CA の曲線（既定 = tee-anchor 既定）

log()  { echo -e "\033[1;32m[bench-provision-tdx]\033[0m $*"; }
warn() { echo -e "\033[1;33m[bench-provision-tdx]\033[0m $*" >&2; }
die()  { echo -e "\033[1;31m[bench-provision-tdx]\033[0m $*" >&2; exit 1; }

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
    "$SCRIPT_DIR/../../../tee-anchor" \
    "$HOME/Develop/tee-anchor/tee-anchor")" || true
[ -n "$TEE_ANCHOR" ] || die "tee-anchor が見つかりません。TEE_ANCHOR=<path> で指定するか PATH を通してください。"

# ---------------------------------------------------------------------------
# 入力 TD Quote の探索
# ---------------------------------------------------------------------------
QUOTE="${QUOTE:-}"
if [ -z "$QUOTE" ]; then
    for c in \
        "${BUNDLE_DIR:-}/quote.dat" \
        "$HOME/Develop/Humane-RAFW-TDX/relying-party/quote.dat" \
        "$HOME/Develop/Humane-RAFW-TDX/quote.dat" \
        "$SCRIPT_DIR/quote.dat"; do
        [ -n "$c" ] && [ -f "$c" ] && { QUOTE="$c"; break; }
    done
fi
[ -n "$QUOTE" ] && [ -f "$QUOTE" ] \
    || die "TD Quote が見つかりません。QUOTE=<path> で指定してください（例: Humane-RAFW-TDX の RA で生成した quote.dat）。"

# ---------------------------------------------------------------------------
# 計測用作業ディレクトリと、署名用 CA の準備（CA 生成は計測に含めない）
# ---------------------------------------------------------------------------
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

CA_KEY="$WORK/ca.key"
CA_CERT="$WORK/ca.crt"
OUT_CRT="$WORK/endorsement.crt"

"$TEE_ANCHOR" ca-init --out-dir "$WORK" --curve "$CA_CURVE" --force >/dev/null 2>&1 \
    || die "署名用 CA の ca-init に失敗しました。"

# 各試行直前に出力物を消すための prepare（計測区間の外で実行する）
PREP_RM="rm -f $OUT_CRT"

# 健全性チェック: provision が 1 回成功し verify が通るか（クリーンな状態から）
$PREP_RM
if "$TEE_ANCHOR" provision --tee-type tdx --quote "$QUOTE" \
        --ca-key "$CA_KEY" --ca-cert "$CA_CERT" --out "$OUT_CRT" >/dev/null 2>&1; then
    if "$TEE_ANCHOR" verify --tee-type tdx --quote "$QUOTE" \
            --org-cert "$OUT_CRT" --org-ca "$CA_CERT" >/dev/null 2>&1; then
        log "sanity: provision→verify OK（発行した endorsement が Chip ID 照合に成功）"
    else
        warn "sanity: provision は成功したが verify が非ゼロ（計測は続行: 発行コスト自体は測れる）"
    fi
else
    die "provision が失敗しました。TD Quote/CA/バイナリの整合を確認してください: $QUOTE"
fi

log "tee-anchor : $TEE_ANCHOR"
log "quote      : $QUOTE ($(stat -c%s "$QUOTE" 2>/dev/null || echo '?') bytes)"
log "ca (curve) : $CA_CURVE  ($CA_KEY)"
log "warmup=$WARMUP runs=$RUNS  out=${OUT_PREFIX}.{md,json}"
echo

# ===========================================================================
# 計測本体
# ===========================================================================
if command -v hyperfine >/dev/null 2>&1; then
    log "hyperfine を使用します。"
    for p in "$TEE_ANCHOR" "$QUOTE" "$CA_KEY" "$CA_CERT" "$OUT_CRT"; do
        case "$p" in *" "*) die "パスに空白が含まれています: '$p' (-N モードでは不可)";; esac
    done
    # --prepare: 各試行直前（計測区間の外）で --out を削除し、毎回新規書出を測る。
    hyperfine -N \
        --warmup "$WARMUP" \
        --min-runs "$RUNS" \
        --prepare "$PREP_RM" \
        --command-name "provision (tdx)" \
            "$TEE_ANCHOR provision --tee-type tdx --quote $QUOTE --ca-key $CA_KEY --ca-cert $CA_CERT --out $OUT_CRT" \
        --export-markdown "${OUT_PREFIX}.md" \
        --export-json "${OUT_PREFIX}.json"
    echo
    log "結果を ${OUT_PREFIX}.md / ${OUT_PREFIX}.json に保存しました。"
else
    warn "hyperfine が無いため bash 簡易計測にフォールバックします。"
    warn "より厳密な計測には 'sudo apt-get install hyperfine' を推奨します。"
    echo

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
                printf "%-20s mean %7.3f +/- %6.3f ms  (min %7.3f, median %7.3f, max %7.3f, n=%d)\n",
                       name, mean, sd, mn, med, mx, runs;
                printf "{\n  \"tool\": \"bash-fallback\",\n  \"runs\": %d, \"warmup\": %d,\n  \"results\": [\n    {\"name\": \"%s\", \"mean_ms\": %.6f, \"stdev_ms\": %.6f, \"min_ms\": %.6f, \"median_ms\": %.6f, \"max_ms\": %.6f}\n  ]\n}\n",
                       runs, '"$WARMUP"', name, mean, sd, mn, med, mx > "'"${OUT_PREFIX}.json"'"
            }'
    }
    bench_one "provision (tdx)" "$TEE_ANCHOR" provision --tee-type tdx --quote "$QUOTE" \
        --ca-key "$CA_KEY" --ca-cert "$CA_CERT" --out "$OUT_CRT"
    echo
    log "結果を ${OUT_PREFIX}.json に保存しました。"
fi

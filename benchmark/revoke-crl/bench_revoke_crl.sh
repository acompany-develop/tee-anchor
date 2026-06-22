#!/usr/bin/env bash
# bench_revoke_crl.sh — `tee-anchor revoke` と `tee-anchor crl-issue` を
# **1 セット**（失効登録 → CRL 再発行）として計測する。
#
# 計測対象 (個別ではなくセットで 1 単位として測る):
#   revoke    : endorsement 証明書を失効 DB に追記
#   crl-issue : 失効 DB から CRL を署名・発行
#   → 1 反復 = 「revoke してから crl-issue する」運用フロー一式
#
# 内訳 (支配項):
#   revoke    = 証明書パース → serial 抽出 → 失効 DB へ追記
#   crl-issue = 失効 DB 読込 → X.509 CRL 構築 → CA 鍵で署名 → 書出
#   いずれもネットワーク往復なし。これらは **TEE 非依存** の純 PKI 操作のため、
#   本フォルダ (revoke-crl/) は TEE 別フォルダの外に置く。
#
# 既存状態の影響排除 (重要):
#   crl-issue のコストは失効 DB のエントリ数に依存する。反復のたびに同じ DB へ
#   revoke を積み増すと DB が単調増加し crl-issue が重くなって計測が歪む。そこで
#   **各試行の直前（計測区間の外）で失効 DB と CRL 出力を削除**し、毎回
#   「空 DB → 1 件 revoke → 1 件 CRL 発行」という同一条件のセットコストを測る。
#   （hyperfine は --prepare、bash フォールバックは反復前の rm -f で実現）
#   署名用 CA と失効対象の endorsement 証明書はスクリプト先頭で 1 度だけ用意し、
#   その生成コストは計測に含めない。
#
# 計測ツール:
#   hyperfine があればそれを使う（revoke && crl-issue を 1 コマンド列として測る。
#   "&&" を使うためシェル経由＝ -N は使わない）。無ければ bash 簡易ループにフォール
#   バックし、2 コマンドを同一計測区間にまとめて測る。
#
# TEE 種別について:
#   計測対象の revoke / crl-issue は **TEE 非依存** の純 PKI 操作のため、どの TEE で
#   発行した endorsement でも結果は本質的に変わらない。ただし失効対象 endorsement を
#   用意する provision には TEE 種別が要る。既定は sgx だが、TEE_TYPE=tdx を指定すると
#   TD Quote から発行した endorsement を失効対象にできる（探索 Quote パスも切替わる）。
#
# 使い方:
#   ./bench_revoke_crl.sh
#   TEE_TYPE=tdx ./bench_revoke_crl.sh                    # TD Quote で失効対象を発行
#   QUOTE=/path/to/quote.dat ./bench_revoke_crl.sh
#   TEE_TYPE=tdx QUOTE=/path/to/td_quote.dat ./bench_revoke_crl.sh
#   RUNS=200 WARMUP=20 ./bench_revoke_crl.sh
#   TEE_ANCHOR=/path/to/tee-anchor ./bench_revoke_crl.sh

set -euo pipefail

WARMUP="${WARMUP:-20}"
RUNS="${RUNS:-200}"
OUT_PREFIX="${OUT_PREFIX:-bench_revoke_crl}"
CA_CURVE="${CA_CURVE:-P-384}"          # 署名 CA の曲線（既定 = tee-anchor 既定）
TEE_TYPE="${TEE_TYPE:-sgx}"            # 失効対象 endorsement を発行する TEE 種別 (sgx|tdx)

case "$TEE_TYPE" in
    sgx|tdx) ;;
    *) echo "TEE_TYPE は sgx か tdx のみ対応します（指定値: $TEE_TYPE）" >&2; exit 1;;
esac
REASON="${REASON:-keyCompromise}"      # revoke の失効理由

log()  { echo -e "\033[1;32m[bench-revoke-crl]\033[0m $*"; }
warn() { echo -e "\033[1;33m[bench-revoke-crl]\033[0m $*" >&2; }
die()  { echo -e "\033[1;31m[bench-revoke-crl]\033[0m $*" >&2; exit 1; }

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

# ---------------------------------------------------------------------------
# 入力 Quote の探索 (失効対象の endorsement を provision するために使用)
# ---------------------------------------------------------------------------
QUOTE="${QUOTE:-}"
if [ -z "$QUOTE" ]; then
    if [ "$TEE_TYPE" = "tdx" ]; then
        cands=( \
            "${BUNDLE_DIR:-}/quote.dat" \
            "$HOME/Develop/Humane-RAFW-TDX/relying-party/quote.dat" \
            "$HOME/Develop/Humane-RAFW-TDX/quote.dat" \
            "$SCRIPT_DIR/quote.dat" )
    else
        cands=( \
            "${BUNDLE_DIR:-}/quote.dat" \
            "$HOME/Develop/Humane-RAFW-MAA-rev/quote.dat" \
            "$HOME/Develop/Humane-RAFW-MAA/quote.dat" \
            "$SCRIPT_DIR/quote.dat" )
    fi
    for c in "${cands[@]}"; do
        [ -n "$c" ] && [ -f "$c" ] && { QUOTE="$c"; break; }
    done
fi
[ -n "$QUOTE" ] && [ -f "$QUOTE" ] \
    || die "${TEE_TYPE^^} Quote が見つかりません。QUOTE=<path> で指定してください（失効対象 endorsement の発行に使用）。"

# ---------------------------------------------------------------------------
# 計測用作業ディレクトリと、CA・失効対象 endorsement の準備（計測に含めない）
# ---------------------------------------------------------------------------
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

CA_KEY="$WORK/ca.key"
CA_CERT="$WORK/ca.crt"
ENDORSE="$WORK/endorsement.crt"
DB="$WORK/revocations.txt"
CRL="$WORK/crl.pem"

"$TEE_ANCHOR" ca-init --out-dir "$WORK" --curve "$CA_CURVE" --force >/dev/null 2>&1 \
    || die "署名用 CA の ca-init に失敗しました。"
"$TEE_ANCHOR" provision --tee-type "$TEE_TYPE" --quote "$QUOTE" \
    --ca-key "$CA_KEY" --ca-cert "$CA_CERT" --out "$ENDORSE" >/dev/null 2>&1 \
    || die "失効対象 endorsement の provision に失敗しました ($TEE_TYPE): $QUOTE"

# 各試行直前に失効 DB と CRL 出力を消すための prepare（計測区間の外で実行）
PREP_RM="rm -f $DB $CRL"

# 健全性チェック: セット (revoke→crl-issue) が 1 回成功し CRL に失効が載るか
$PREP_RM
if "$TEE_ANCHOR" revoke --ca-cert "$CA_CERT" --cert "$ENDORSE" --reason "$REASON" --db "$DB" >/dev/null 2>&1 \
   && "$TEE_ANCHOR" crl-issue --ca-key "$CA_KEY" --ca-cert "$CA_CERT" --out "$CRL" --db "$DB" >/dev/null 2>&1; then
    n_revoked="$(openssl crl -in "$CRL" -noout -text 2>/dev/null | grep -c 'Serial Number' || true)"
    log "sanity: revoke→crl-issue OK（CRL に失効 ${n_revoked} 件を反映）"
else
    die "revoke / crl-issue が失敗しました。CA/endorsement/バイナリの整合を確認してください。"
fi

log "tee-anchor : $TEE_ANCHOR"
log "endorsement: $ENDORSE ($TEE_TYPE quote から発行, CA 曲線 $CA_CURVE, 失効理由 $REASON)"
log "warmup=$WARMUP runs=$RUNS  out=${OUT_PREFIX}.{md,json}"
echo

# ===========================================================================
# 計測本体（revoke + crl-issue を 1 セットとして測る）
# ===========================================================================
if command -v hyperfine >/dev/null 2>&1; then
    log "hyperfine を使用します（revoke && crl-issue を 1 コマンド列として計測）。"
    for p in "$TEE_ANCHOR" "$CA_KEY" "$CA_CERT" "$ENDORSE" "$DB" "$CRL"; do
        case "$p" in *" "*) die "パスに空白が含まれています: '$p'";; esac
    done
    # --prepare で毎回 DB/CRL をクリーンにし、同一条件のセットコストを測る。
    hyperfine \
        --warmup "$WARMUP" \
        --min-runs "$RUNS" \
        --prepare "$PREP_RM" \
        --command-name "revoke + crl-issue (set)" \
            "$TEE_ANCHOR revoke --ca-cert $CA_CERT --cert $ENDORSE --reason $REASON --db $DB && $TEE_ANCHOR crl-issue --ca-key $CA_KEY --ca-cert $CA_CERT --out $CRL --db $DB" \
        --export-markdown "${OUT_PREFIX}.md" \
        --export-json "${OUT_PREFIX}.json"
    echo
    log "結果を ${OUT_PREFIX}.md / ${OUT_PREFIX}.json に保存しました。"
else
    warn "hyperfine が無いため bash 簡易計測にフォールバックします。"
    warn "より厳密な計測には 'sudo apt-get install hyperfine' を推奨します。"
    echo

    # bash フォールバック: revoke と crl-issue を同一計測区間にまとめて測る。
    # 各反復の直前（計測区間の外）で $PREP_RM を実行して DB/CRL をクリーンにする。
    run_set() {  # 計測対象の 1 セット
        "$TEE_ANCHOR" revoke --ca-cert "$CA_CERT" --cert "$ENDORSE" --reason "$REASON" --db "$DB" >/dev/null 2>&1 || true
        "$TEE_ANCHOR" crl-issue --ca-key "$CA_KEY" --ca-cert "$CA_CERT" --out "$CRL" --db "$DB" >/dev/null 2>&1 || true
    }

    for ((i=0; i<WARMUP; i++)); do $PREP_RM; run_set; done
    ns=()
    for ((i=0; i<RUNS; i++)); do
        $PREP_RM                          # 計測区間の外でクリーンアップ
        t0=$(date +%s%N); run_set; t1=$(date +%s%N)
        ns+=( $((t1 - t0)) )
    done

    printf '%s\n' "${ns[@]}" | awk -v name="revoke + crl-issue (set)" -v runs="$RUNS" -v warmup="$WARMUP" '
        { v=$1/1e6; a[NR]=v; s+=v; if(NR==1||v<mn)mn=v; if(NR==1||v>mx)mx=v }
        END{
            mean=s/NR;
            for(i=1;i<=NR;i++){d=a[i]-mean; var+=d*d}
            sd=(NR>1)?sqrt(var/NR):0;
            n=asort(a);
            med=(n%2)?a[int(n/2)+1]:(a[n/2]+a[n/2+1])/2;
            printf "%-26s mean %7.3f +/- %6.3f ms  (min %7.3f, median %7.3f, max %7.3f, n=%d)\n",
                   name, mean, sd, mn, med, mx, runs;
            printf "{\n  \"tool\": \"bash-fallback\",\n  \"runs\": %d, \"warmup\": %d,\n  \"results\": [\n    {\"name\": \"%s\", \"mean_ms\": %.6f, \"stdev_ms\": %.6f, \"min_ms\": %.6f, \"median_ms\": %.6f, \"max_ms\": %.6f}\n  ]\n}\n",
                   runs, warmup, name, mean, sd, mn, med, mx > "'"${OUT_PREFIX}.json"'"
        }'
    echo
    log "結果を ${OUT_PREFIX}.json に保存しました。"
fi

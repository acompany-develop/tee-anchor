#!/bin/sh
# get-cca-token.sh — Realm guest 内で実行する CCA Attestation Token 取得スクリプト
#
# Realm(buildroot) は busybox/ash 環境なので POSIX sh で書いてある（bashism 禁止）。
# Realm には curl/scp が無いため、取得した CBOR トークンを base64 でコンソールに
# 出力する。ホスト側で extract-cca-token.sh に食わせて cca-token.cbor を復元する。
#
# Realm コンソールでの使い方（root ログイン後）:
#   - このファイルの中身を貼り付けて実行するか、共有経由で持ち込んで `sh get-cca-token.sh`
#
# 出力は ---8<--- BEGIN/END CCA-TOKEN-B64 ---8<--- で囲まれる。ホスト側はこの 2 行の
# 間だけを取り出して base64 -d すればよい。
set -e

OUT="${OUT:-cca-token.cbor}"

# cca-workload-attestation: report サブコマンドで Platform/Realm トークンを取得し
# CBOR を cca-token.cbor に保存する（JSON はコンソールにも出る）。
if ! command -v cca-workload-attestation >/dev/null 2>&1; then
    echo "[error] cca-workload-attestation が見つかりません（Realm guest 内で実行していますか？）" >&2
    exit 1
fi

echo "==> cca-workload-attestation report"
cca-workload-attestation report

# report は実行ディレクトリに cca-token.cbor を保存する。名前が違う場合に備え探す。
if [ ! -f "$OUT" ]; then
    found=$(ls -1 *.cbor 2>/dev/null | head -1 || true)
    [ -n "$found" ] && OUT="$found"
fi
[ -f "$OUT" ] || { echo "[error] $OUT が生成されませんでした" >&2; exit 1; }

echo
echo "==> $OUT ($(wc -c < "$OUT") bytes) を base64 で出力します。下記 2 行の間をホストへコピー:"
echo "---8<--- BEGIN CCA-TOKEN-B64 ---8<---"
base64 "$OUT"
echo "---8<--- END CCA-TOKEN-B64 ---8<---"

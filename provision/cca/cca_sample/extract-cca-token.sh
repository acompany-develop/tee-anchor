#!/usr/bin/env bash
# extract-cca-token.sh — Realm から base64 で出力された CCA token をホスト側で復元する
#
# get-cca-token.sh が Realm コンソールに出した
#   ---8<--- BEGIN CCA-TOKEN-B64 ---8<---
#   <base64...>
#   ---8<--- END CCA-TOKEN-B64 ---8<---
# のブロックを、マーカーごと貼り付け（またはログファイルを渡し）て cca-token.cbor を復元する。
#
# 使い方:
#   ./extract-cca-token.sh < pasted.txt          # マーカー込みのテキストを stdin で
#   ./extract-cca-token.sh realm-console.log      # ログファイルから抽出
#   pbpaste | ./extract-cca-token.sh              # クリップボードから
#
# 出力: cca-token.cbor （TEE Anchor の --report に渡す入力）
set -euo pipefail

OUT="${OUT:-cca-token.cbor}"
BEGIN="BEGIN CCA-TOKEN-B64"
END="END CCA-TOKEN-B64"

src() { if [ "$#" -ge 1 ] && [ -n "${1:-}" ]; then cat "$1"; else cat; fi; }

# マーカー間を取り出し、マーカー行自体は捨て、base64 として不正な行（空白等）を除去。
b64="$(src "${1:-}" \
    | awk "/$BEGIN/{f=1;next} /$END/{f=0} f" \
    | tr -d '\r' \
    | grep -E '^[A-Za-z0-9+/=]+$' || true)"

if [ -z "$b64" ]; then
    echo "[error] base64 ブロックが見つかりません（$BEGIN ～ $END で囲まれていますか？）" >&2
    exit 1
fi

echo "$b64" | base64 -d > "$OUT"
echo "restored: $OUT ($(wc -c < "$OUT") bytes)"
# 先頭バイトを軽く確認（CBOR tag 399 = EAT collection は 0xD9 0x018F で始まることが多い）
head -c 4 "$OUT" | xxd 2>/dev/null | head -1 || true

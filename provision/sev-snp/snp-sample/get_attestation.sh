#!/usr/bin/env bash
# get_attestation.sh — SEV-SNP Attestation Report + VCEK 証明書チェーン取得サンプル
#
# TEE Anchor の provision / verify (SEV-SNP 経路) に渡す入力を実機で生成する
# 評価用ハーネス。SGX 版 (provision/sgx/sgx_sample) の SEV-SNP 対応版にあたる。
# SGX サンプルと同じく、これは TEE Anchor 本体 (Endorser/Verifier) の一部ではなく
# Attester 側の入力を作るための補助ツールである。
#
# やること:
#   1. snpguest (https://github.com/virtee/snpguest) が無ければ、y/N 確認の上で
#      ~/snpguest にクローンしてソースからビルド (Rust toolchain が無ければ rustup で導入)
#   2. /dev/sev-guest 経由で Attestation Report を取得 -> report.bin
#   3. Report に基づき AMD KDS から証明書チェーンを取得
#      -> certs/ark.pem (AMD Root Key) / certs/ask.pem (AMD SEV Key) / certs/vcek.pem
#   4. snpguest verify で取得物の整合性を確認 (sanity check)
#
# 使い方:
#   ./get_attestation.sh                              # 一括実行
#   SNP_VMPL=0 ./get_attestation.sh                   # Report 要求の VMPL を明示
#   SNP_PROCESSOR_MODEL=milan ./get_attestation.sh    # KDS 問い合わせのプロセッサ世代を明示
#                                                     # (既定は Report から自動導出。
#                                                     #  Report が v2 以前だと導出できず
#                                                     #  失敗するため、その場合に指定する)
#
# 非 root での実行を想定し、必要箇所 (apt / Report 取得) のみ内部で sudo を使う。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"
REPORT_PATH="$SCRIPT_DIR/report.bin"
REQUEST_PATH="$SCRIPT_DIR/request-data.txt"

# snpguest はユーザのホーム直下に展開し、その時点の最新版 (main) を使う
SNPGUEST_DIR="$HOME/snpguest"
SNPGUEST_REPO="https://github.com/virtee/snpguest"

log()  { echo -e "\033[1;32m[snp-sample]\033[0m $*"; }
warn() { echo -e "\033[1;33m[snp-sample]\033[0m $*" >&2; }
die()  { echo -e "\033[1;31m[snp-sample]\033[0m $*" >&2; exit 1; }

# ----------------------------------------------------------------------------
# 0. プリフライト: SEV-SNP ゲストであること
# ----------------------------------------------------------------------------
[ -e /dev/sev-guest ] || die "/dev/sev-guest がありません。SEV-SNP ゲスト上で実行してください。"

# ----------------------------------------------------------------------------
# 1. snpguest の確保 (PATH -> ~/snpguest/target/release -> y/N 確認の上で導入)
# ----------------------------------------------------------------------------
find_snpguest() {
    if command -v snpguest >/dev/null 2>&1; then
        command -v snpguest
    elif [ -x "$SNPGUEST_DIR/target/release/snpguest" ]; then
        echo "$SNPGUEST_DIR/target/release/snpguest"
    else
        echo ""
    fi
}

install_snpguest() {
    # 勝手にインストールせず、ユーザに確認を取る
    echo -n "snpguest が見つかりません。$SNPGUEST_DIR に最新版 (main) をインストールしますか？ [y/N] "
    read -r answer
    case "$answer" in
        [yY]|[yY][eE][sS]) ;;
        *) die "中止しました。snpguest を手動で導入するか PATH を通してから再実行してください。" ;;
    esac

    # ビルド依存 (snpguest は openssl 系 crate を使うため libssl-dev / pkg-config が要る)
    log "ビルド依存パッケージを導入します (sudo)。"
    sudo apt-get install -y build-essential curl git pkg-config libssl-dev

    # Rust toolchain (snpguest README 記載の手順)
    #   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    #   source "$HOME/.cargo/env"
    if [ -f "$HOME/.cargo/env" ]; then
        # 導入済みだが PATH 未設定のケースを先に救う
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env"
    fi
    if ! command -v cargo >/dev/null 2>&1; then
        log "Rust toolchain を rustup で導入します (ユーザ領域のみ、sudo 不要)。"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env"
    fi

    # ~/snpguest に最新版 (main) をクローンしてビルド (snpguest README の cargo build -r)
    if [ ! -d "$SNPGUEST_DIR" ]; then
        git clone --depth 1 "$SNPGUEST_REPO" "$SNPGUEST_DIR"
    else
        warn "$SNPGUEST_DIR が既に存在するため、クローンはスキップしてそのままビルドします。"
    fi
    (cd "$SNPGUEST_DIR" && cargo build -r)
    log "snpguest を $SNPGUEST_DIR/target/release/snpguest に配置しました。"
}

SNPGUEST="$(find_snpguest)"
if [ -z "$SNPGUEST" ]; then
    install_snpguest
    SNPGUEST="$SNPGUEST_DIR/target/release/snpguest"
fi
log "snpguest: $SNPGUEST ($("$SNPGUEST" --version 2>/dev/null || echo 'version unknown'))"

# ----------------------------------------------------------------------------
# 2. Attestation Report の取得
#    /dev/sev-guest の ioctl は root 権限が要るため、ここだけ sudo。
#    request data は --random で 64 バイト乱数を生成し、参照用に保存される。
# ----------------------------------------------------------------------------
log "Attestation Report を取得します (sudo)。"
VMPL_ARGS=()
if [ -n "${SNP_VMPL:-}" ]; then
    VMPL_ARGS=(--vmpl "$SNP_VMPL")
fi
sudo "$SNPGUEST" report "$REPORT_PATH" "$REQUEST_PATH" --random "${VMPL_ARGS[@]}"
# sudo で作られたファイルの所有権を実行ユーザへ戻す
sudo chown "$(id -u):$(id -g)" "$REPORT_PATH" "$REQUEST_PATH"
log "Report: $REPORT_PATH ($(wc -c < "$REPORT_PATH") bytes)"

# ----------------------------------------------------------------------------
# 3. AMD KDS から証明書チェーンを取得
#    - ARK/ASK (CA チェーン): 既定では Report からプロセッサ世代を自動導出。
#      SNP_PROCESSOR_MODEL を指定した場合はそれを positional で渡す。
#    - VCEK: Report 内の CHIP_ID + TCB に基づく URL で KDS から取得。
# ----------------------------------------------------------------------------
mkdir -p "$CERTS_DIR"

log "AMD KDS から ARK/ASK (CA チェーン) を取得します。"
if [ -n "${SNP_PROCESSOR_MODEL:-}" ]; then
    "$SNPGUEST" fetch ca pem "$CERTS_DIR" "$SNP_PROCESSOR_MODEL"
else
    "$SNPGUEST" fetch ca pem "$CERTS_DIR" --report "$REPORT_PATH"
fi

log "AMD KDS から VCEK を取得します。"
"$SNPGUEST" fetch vcek pem "$CERTS_DIR" "$REPORT_PATH"

# ----------------------------------------------------------------------------
# 4. sanity check
#    TEE Anchor は後でこれらを独立に検証するが、取得物がそもそも壊れていないか
#    snpguest 自身の verify で確認しておく。
# ----------------------------------------------------------------------------
log "取得した証明書チェーンを検証します (ARK -> ASK -> VCEK)。"
"$SNPGUEST" verify certs "$CERTS_DIR"

log "Attestation Report の署名を VCEK で検証します。"
"$SNPGUEST" verify attestation "$CERTS_DIR" "$REPORT_PATH"

# ----------------------------------------------------------------------------
# まとめ
# ----------------------------------------------------------------------------
log "完了。生成物:"
echo "  $REPORT_PATH            ... Attestation Report (TEE Anchor への入力)"
echo "  $REQUEST_PATH      ... Report 要求に使った 64B request data (参照用)"
echo "  $CERTS_DIR/ark.pem           ... AMD Root Key (自己署名 root)"
echo "  $CERTS_DIR/ask.pem           ... AMD SEV Key (intermediate)"
echo "  $CERTS_DIR/vcek.pem          ... VCEK (leaf; CHIP_ID を拡張に含む)"
echo ""
echo "report.bin と certs/ が TEE Anchor の provision / verify (SEV-SNP 経路) の入力になります。"

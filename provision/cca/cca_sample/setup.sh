#!/usr/bin/env bash
#
# setup.sh — Arm CCA RME スタック（QEMU フルエミュレーション）の環境構築
#
# TDX/SNP サンプル (provision/tdx/tdx_sample, provision/sev-snp/snp-sample) の
# Arm CCA 版。ただし CCA は実機が存在しないため、QEMU(TCG) 上に
#   TF-A(EL3) + TF-RMM(R-EL2) + Host Linux/KVM + Realm guest
# のフルスタックを丸ごとビルドし、その中で CCA Attestation Token を生成する。
#
# 手順は Linaro "Building an RME stack for QEMU"（OP-TEE ビルド環境方式）に準拠し、
# 同梱の cca-ra-doc.pdf（Arm CCA RA 調査）で実証済みの recipe をそのまま自動化したもの。
#
# このスクリプトは「証拠（CCA token）を生成するためのハーネス」を用意するだけで、
# TEE Anchor 本体（provision/verify）は生成済み cca-token.cbor をファイル入力として
# 消費する。SGX の sample_app / TDX の get_quote / SNP の get_attestation.sh と同じ位置づけ。
#
# 使い方:
#   ./setup.sh                # 一括（prereqs → fetch → build）。数十GB・長時間。
#   sudo ./setup.sh --prereqs # apt 前提パッケージのみ（sudo 必須）
#   ./setup.sh --fetch        # repo init + sync のみ
#   ./setup.sh --build        # make toolchains + make のみ（fetch 済み前提）
#   ./setup.sh --check        # 構築状況の診断のみ（何もインストール/ビルドしない）
#
# 上書き可能な環境変数:
#   CCA_WORKSPACE   スタックを展開/ビルドするディレクトリ (既定: $HOME/cca)
#   CCA_MANIFEST_BRANCH  repo マニフェストのブランチ (既定: cca/v10)
#   CCA_MANIFEST_FILE    マニフェストファイル (既定: qemu_v8_cca.xml = Virt ボード)
#   JOBS            ビルド並列度 (既定: nproc)
#
set -euo pipefail

CCA_WORKSPACE="${CCA_WORKSPACE:-$HOME/cca}"
CCA_MANIFEST_URL="https://git.codelinaro.org/linaro/dcap/op-tee-4.2.0/manifest.git"
CCA_MANIFEST_BRANCH="${CCA_MANIFEST_BRANCH:-cca/v10}"
CCA_MANIFEST_FILE="${CCA_MANIFEST_FILE:-qemu_v8_cca.xml}"
JOBS="${JOBS:-$(nproc)}"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# ---- 事前チェック -----------------------------------------------------------
preflight() {
    [ "$(uname -m)" = "x86_64" ] || warn "x86_64 以外を検出: $(uname -m)（QEMU TCG なので動くが未検証）"
    command -v apt-get >/dev/null || die "apt-get が見つかりません。Ubuntu/Debian 系で実行してください"
    [ -r /etc/os-release ] || die "/etc/os-release が読めません"
    # shellcheck disable=SC1091
    . /etc/os-release
    [ "${VERSION_CODENAME:-}" = "noble" ] || \
        warn "Ubuntu 24.04(noble) で検証済み。検出: ${PRETTY_NAME:-unknown}（続行はします）"
}

# ---- 1. 前提パッケージ ------------------------------------------------------
# 2 系統を導入する:
#   (A) RME stack prereqs            … repo / ninja / dtc / cmake 等、ビルド本体
#   (B) OP-TEE prereqs               … 本ビルド環境は OP-TEE のビルドシステムを
#                                       流用するため OP-TEE の依存も必要
# (cca-ra-doc.pdf「必要なライブラリのインストール」に準拠。netcat→netcat-openbsd,
#  libncurses5-dev→libncurses-dev に読み替え済み)
install_prereqs() {
    log "前提パッケージを導入（RME stack + OP-TEE。sudo 必須）"
    sudo apt-get update -y
    # (A) RME stack prerequisites
    sudo apt-get install -y \
        repo \
        python3-pyelftools python3-venv \
        acpica-tools \
        libssl-dev \
        libglib2.0-dev libpixman-1-dev \
        device-tree-compiler \
        flex bison \
        make cmake ninja-build curl rsync jq
    # (B) OP-TEE prerequisites
    sudo apt-get install -y \
        adb acpica-tools autoconf automake bc bison build-essential \
        ccache cpio cscope curl device-tree-compiler e2tools expect \
        fastboot flex ftp-upload gdisk git libgnutls28-dev libattr1-dev \
        libcap-ng-dev libfdt-dev libftdi-dev libglib2.0-dev libgmp3-dev \
        libhidapi-dev libmpc-dev libncurses-dev libpixman-1-dev \
        libslirp-dev libssl-dev libtool libusb-1.0-0-dev make mtools \
        netcat-openbsd ninja-build python3-cryptography python3-pip \
        python3-pyelftools python3-serial python3-tomli python-is-python3 \
        rsync swig unzip uuid-dev wget xdg-utils xsltproc xterm \
        xz-utils zlib1g-dev
    log "前提パッケージ導入 完了"
}

# ---- 2. ソース取得 (repo init + sync) ---------------------------------------
fetch_sources() {
    command -v repo >/dev/null || die "repo が見つかりません。先に 'sudo ./setup.sh --prereqs' を実行してください"
    log "ワークスペース: $CCA_WORKSPACE （manifest: $CCA_MANIFEST_BRANCH / $CCA_MANIFEST_FILE）"
    mkdir -p "$CCA_WORKSPACE"
    cd "$CCA_WORKSPACE"
    if [ ! -d .repo ]; then
        log "repo init"
        repo init -u "$CCA_MANIFEST_URL" -b "$CCA_MANIFEST_BRANCH" -m "$CCA_MANIFEST_FILE"
    else
        log ".repo を検出。init はスキップ"
    fi
    log "repo sync -j$JOBS （数 GB のダウンロード。時間がかかります）"
    repo sync -j"$JOBS" --no-clone-bundle
    log "ソース取得 完了"
}

# ---- 3. ビルド (toolchains → 本体) ------------------------------------------
build_stack() {
    [ -d "$CCA_WORKSPACE/build" ] || die "$CCA_WORKSPACE/build が無い。先に --fetch を実行してください"
    cd "$CCA_WORKSPACE/build"
    log "make -j$JOBS toolchains （クロスツールチェーンの取得/構築）"
    make -j"$JOBS" toolchains
    log "make -j$JOBS （TF-A/RMM/EDK2/カーネル×2/rootfs/QEMU をビルド。最も時間がかかる）"
    make -j"$JOBS"
    log "ビルド 完了"
}

# ---- 診断 -------------------------------------------------------------------
check_env() {
    log "構築状況の診断（workspace: $CCA_WORKSPACE）"
    local ok=1
    if command -v repo >/dev/null; then echo "  [ok]   repo 検出"; else echo "  [NG]   repo 未導入（--prereqs）"; ok=0; fi
    if [ -d "$CCA_WORKSPACE/.repo" ]; then echo "  [ok]   repo workspace 初期化済み"; else echo "  [NG]   $CCA_WORKSPACE/.repo 無し（--fetch）"; ok=0; fi
    if [ -d "$CCA_WORKSPACE/build" ]; then echo "  [ok]   build/ 検出"; else echo "  [NG]   build/ 無し（--fetch）"; ok=0; fi
    # 主要成果物（Virt ボード）
    local img="$CCA_WORKSPACE/out/bin/Image"
    local rootfs="$CCA_WORKSPACE/out-br/images/rootfs.cpio"
    if [ -f "$img" ]; then echo "  [ok]   Realm/Host カーネル: $img"; else echo "  [--]   $img 未生成（--build 後に出現）"; ok=0; fi
    if [ -f "$rootfs" ]; then echo "  [ok]   rootfs.cpio: $rootfs"; else echo "  [--]   $rootfs 未生成（--build 後に出現）"; ok=0; fi
    if [ -x "$CCA_WORKSPACE/build/soc_term.py" ] || [ -f "$CCA_WORKSPACE/build/soc_term.py" ]; then
        echo "  [ok]   soc_term.py（コンソール中継）検出"; else echo "  [--]   soc_term.py 未検出"; fi
    echo
    if [ "$ok" = 1 ]; then
        log "診断 OK。'make run' で QEMU を起動できます（README 参照）"
    else
        warn "未充足あり。'./setup.sh'（一括）か該当フェーズを実行してください"
        return 1
    fi
}

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

main() {
    case "${1:-}" in
        --check)    preflight; check_env; exit $? ;;
        --prereqs)  preflight; install_prereqs; exit 0 ;;
        --fetch)    preflight; fetch_sources; exit 0 ;;
        --build)    preflight; build_stack; exit 0 ;;
        -h|--help)  usage; exit 0 ;;
        "")         ;;  # 一括
        *)          die "unknown option: $1 （--prereqs/--fetch/--build/--check/--help）" ;;
    esac
    preflight
    install_prereqs
    fetch_sources
    build_stack
    echo
    check_env || true
    echo
    log "完了。次は 'make run' で QEMU を起動 → README の手順で Realm を起動し token 取得。"
}

main "$@"

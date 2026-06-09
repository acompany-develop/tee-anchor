#!/usr/bin/env bash
#
# setup.sh — 最小 TD Quote 取得サンプルの環境構築（Ubuntu 24.04 / Intel APT リポジトリ方式）
#
# SGX サンプル (provision/sgx/sgx_sample/setup.sh) の TDX 版。SGX と違い
# SDK (.bin) も Enclave 署名ツールも不要で、libtdx_attest と DCAP ランタイムを
# Intel 公式 APT リポジトリから入れるだけ。Quote 生成はホスト側 QGS が担うため
# ゲスト (TD) 側に QGS は不要。
#
# QCNL 設定 (/etc/sgx_default_qcnl.conf) は libsgx-dcap-default-qpl の導入時に
# 既定ファイル（Intel PCS 直フェッチ）が自動配置されるため、本スクリプトでは
# 上書きしない。自前 PCCS を使う場合のみ手動で編集すること。
#
# 使い方:
#   sudo ./setup.sh            # 一括構築（make 未導入のクリーン環境はこれを直接実行）
#   ./setup.sh --check         # 構築せず現状診断のみ
#
# 上書き可能な環境変数:
#   SGX_APT_DISTRO   APT リポジトリのコードネーム (既定: /etc/os-release の VERSION_CODENAME)
#
set -euo pipefail

SGX_APT_KEY_URL="https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key"
SGX_APT_REPO="https://download.01.org/intel-sgx/sgx_repo/ubuntu"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# ---- 事前チェック -----------------------------------------------------------
preflight() {
    [ "$(uname -m)" = "x86_64" ] || die "x86_64 以外は非対応です (uname -m: $(uname -m))"
    command -v apt-get >/dev/null || die "apt-get が見つかりません。Ubuntu/Debian 系で実行してください"
    [ -r /etc/os-release ] || die "/etc/os-release が読めません"
    # shellcheck disable=SC1091
    . /etc/os-release
    SGX_APT_DISTRO="${SGX_APT_DISTRO:-${VERSION_CODENAME:-noble}}"
    [ "${VERSION_CODENAME:-}" = "noble" ] || \
        warn "Ubuntu 24.04(noble) 想定です。検出: ${PRETTY_NAME:-unknown} (続行はします)"
    command -v sudo >/dev/null || die "sudo が必要です"
}

# ---- 1. ビルド/取得用の前提パッケージ ---------------------------------------
install_prereqs() {
    log "前提パッケージを導入 (build-essential, curl, gnupg 等)"
    sudo apt-get update -y
    sudo apt-get install -y --no-install-recommends \
        build-essential make wget curl gnupg ca-certificates pkg-config
}

# ---- 2. Intel SGX APT リポジトリ登録 ----------------------------------------
add_apt_repo() {
    log "Intel SGX APT リポジトリを登録 (distro: $SGX_APT_DISTRO)"
    sudo install -d -m 0755 /etc/apt/keyrings
    curl -fsSL "$SGX_APT_KEY_URL" | sudo gpg --dearmor --yes -o /etc/apt/keyrings/intel-sgx.gpg
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx.gpg] $SGX_APT_REPO $SGX_APT_DISTRO main" \
        | sudo tee /etc/apt/sources.list.d/intel-sgx.list >/dev/null
    sudo apt-get update -y
}

# ---- 3. TDX attest ランタイム + 開発ヘッダ + QPL ----------------------------
#  libtdx-attest      : tdx_att_get_quote() 本体 (libtdx_attest.so)
#  libtdx-attest-dev  : tdx_attest.h（ビルドに必要）
#  libsgx-dcap-default-qpl : コラテラル取得 (QPL)。導入時に
#                            /etc/sgx_default_qcnl.conf の既定が自動配置される。
#  libsgx-dcap-ql     : DCAP Quoting ライブラリ（依存関係の補完用）
install_tdx_packages() {
    log "TDX attest ランタイム / 開発パッケージ / QPL を導入"
    sudo apt-get install -y \
        libtdx-attest libtdx-attest-dev \
        libsgx-dcap-default-qpl \
        libsgx-dcap-ql
}

# ---- 診断 -------------------------------------------------------------------
check_env() {
    log "環境診断"
    local ok=1

    if [ -e /dev/tdx_guest ]; then
        echo "  [ok]   TDX ゲストデバイス: /dev/tdx_guest"
    else
        echo "  [NG]   /dev/tdx_guest が見つかりません（TDX ゲスト(TD)上で実行していますか？）"; ok=0
    fi

    if ldconfig -p 2>/dev/null | grep -q libtdx_attest; then
        echo "  [ok]   libtdx_attest 検出"
    else
        echo "  [NG]   libtdx_attest が見つかりません（libtdx-attest 未導入）"; ok=0
    fi

    if [ -f /usr/include/tdx_attest.h ] || ls /usr/include/**/tdx_attest.h >/dev/null 2>&1; then
        echo "  [ok]   tdx_attest.h 検出"
    else
        echo "  [NG]   tdx_attest.h が見つかりません（libtdx-attest-dev 未導入）"; ok=0
    fi

    if ldconfig -p 2>/dev/null | grep -q dcap_quoteprov; then
        echo "  [ok]   libdcap_quoteprov (QPL) 検出"
    else
        echo "  [NG]   libdcap_quoteprov (QPL) が見つかりません"; ok=0
    fi

    if [ -f /etc/sgx_default_qcnl.conf ]; then
        echo "  [ok]   /etc/sgx_default_qcnl.conf 配置済み（パッケージ既定）"
    else
        echo "  [warn] /etc/sgx_default_qcnl.conf が未配置（生成のみなら不要。検証時に必要）"
    fi

    echo
    if [ "$ok" = 1 ]; then
        log "診断 OK。'make run' で quote.dat を生成できます（必要に応じ sudo）"
    else
        warn "未充足の項目があります。上記 [NG] を解消してください"
        return 1
    fi
}

main() {
    preflight
    if [ "${1:-}" = "--check" ]; then
        check_env
        exit $?
    fi
    install_prereqs
    add_apt_repo
    install_tdx_packages
    echo
    check_env || true
    echo
    log "完了。'make && ./get_quote' で quote.dat を取得できます。"
}

main "$@"

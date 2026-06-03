#!/usr/bin/env bash
#
# setup.sh — SGX 最小 Quote 取得サンプルの環境構築（Ubuntu 24.04 / Intel APT リポジトリ方式）
#
# Humane-RAFW-MAA / -DCAP の README が行う「SGXSDK + DCAP ランタイム導入 →
# /etc/sgx_default_qcnl.conf 配置 → aesmd 再起動」を、ソースビルド無しで自動化したもの。
# 依存パッケージは Intel 公式 APT リポジトリから、SDK のみ公式 .bin インストーラから入れる
# （SDK は APT リポジトリに含まれないため）。
#
# 使い方:
#   ./setup.sh                 # 一括構築
#   ./setup.sh --check         # 構築せず現状診断のみ
#   QCNL_MODE=keep ./setup.sh  # /etc/sgx_default_qcnl.conf を上書きしない
#   FORCE_SDK=1 ./setup.sh     # SDK を再インストール
#
# 上書き可能な環境変数:
#   SGX_PREFIX       SDK 導入先プレフィックス        (既定: /opt/intel)
#   SGX_APT_DISTRO   APT リポジトリのコードネーム    (既定: /etc/os-release の VERSION_CODENAME)
#   SDK_DISTRO       SDK .bin の distro フォルダ名   (既定: ubuntu24.04-server)
#   SGX_SDK_BIN_URL  SDK .bin の直 URL（指定時は自動探索をスキップ）
#   QCNL_MODE        azure | keep                    (既定: azure = 同梱 conf で上書き)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SGX_PREFIX="${SGX_PREFIX:-/opt/intel}"
SGX_SDK_DIR="$SGX_PREFIX/sgxsdk"
SDK_DISTRO="${SDK_DISTRO:-ubuntu24.04-server}"
SDK_BASE="https://download.01.org/intel-sgx/sgx-linux"
SGX_APT_KEY_URL="https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key"
SGX_APT_REPO="https://download.01.org/intel-sgx/sgx_repo/ubuntu"
QCNL_MODE="${QCNL_MODE:-azure}"

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
        build-essential make wget curl gnupg ca-certificates \
        libssl-dev libcurl4-openssl-dev pkg-config
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

# ---- 3. DCAP / PSW ランタイム + 開発ヘッダ ----------------------------------
#  out-of-proc モードでの Quote 生成に必要な AESM プラグインと AE 群を含む。
install_sgx_packages() {
    log "SGX PSW / DCAP ランタイム・開発パッケージを導入"
    sudo apt-get install -y \
        libsgx-headers \
        libsgx-enclave-common libsgx-enclave-common-dev \
        libsgx-urts libsgx-launch libsgx-epid libsgx-quote-ex \
        libsgx-dcap-ql libsgx-dcap-ql-dev \
        libsgx-dcap-default-qpl libsgx-dcap-default-qpl-dev \
        libsgx-ae-pce libsgx-ae-qe3 libsgx-ae-id-enclave \
        sgx-aesm-service \
        libsgx-aesm-launch-plugin libsgx-aesm-ecdsa-plugin \
        libsgx-aesm-pce-plugin libsgx-aesm-quote-ex-plugin
}

# ---- 4. SGXSDK (.bin インストーラ) ------------------------------------------
install_sdk() {
    if [ -f "$SGX_SDK_DIR/environment" ] && [ -z "${FORCE_SDK:-}" ]; then
        log "SDK は既に導入済み: $SGX_SDK_DIR (再導入は FORCE_SDK=1)"
        return
    fi

    local url="${SGX_SDK_BIN_URL:-}"
    if [ -z "$url" ]; then
        log "最新 SDK バージョンを download.01.org から探索"
        local ver bin
        ver="$(curl -fsSL "$SDK_BASE/" \
            | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?/' | tr -d '/' | sort -V | tail -n1)"
        [ -n "$ver" ] || die "SDK バージョンの探索に失敗。SGX_SDK_BIN_URL を手動指定してください"
        bin="$(curl -fsSL "$SDK_BASE/$ver/distro/$SDK_DISTRO/" \
            | grep -oE 'sgx_linux_x64_sdk_[0-9.]+\.bin' | sort -u | tail -n1)"
        [ -n "$bin" ] || die "distro=$SDK_DISTRO の SDK .bin が見つかりません。SGX_SDK_BIN_URL を指定してください"
        url="$SDK_BASE/$ver/distro/$SDK_DISTRO/$bin"
    fi

    log "SDK をダウンロード: $url"
    local tmp; tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    curl -fsSL "$url" -o "$tmp/sgxsdk.bin"
    chmod +x "$tmp/sgxsdk.bin"
    log "SDK を $SGX_PREFIX に非対話インストール"
    sudo "$tmp/sgxsdk.bin" --prefix="$SGX_PREFIX"
}

# ---- 5. QCNL 設定（コラテラル取得設定） -------------------------------------
configure_qcnl() {
    local sample="$SCRIPT_DIR/sgx_default_qcnl.conf"
    case "$QCNL_MODE" in
        keep)
            log "QCNL_MODE=keep: /etc/sgx_default_qcnl.conf は変更しません"
            ;;
        azure)
            [ -f "$sample" ] || die "同梱 QCNL 設定が見つかりません: $sample"
            if [ -f /etc/sgx_default_qcnl.conf ]; then
                local bak="/etc/sgx_default_qcnl.conf.bak.$(date +%Y%m%d%H%M%S)"
                log "既存 QCNL 設定を退避: $bak"
                sudo cp -p /etc/sgx_default_qcnl.conf "$bak"
            fi
            log "同梱 QCNL 設定 (Azure THIM 想定) を /etc/sgx_default_qcnl.conf に配置"
            sudo install -m 0644 -o root -g root "$sample" /etc/sgx_default_qcnl.conf
            ;;
        *)
            die "未知の QCNL_MODE: $QCNL_MODE (azure | keep)"
            ;;
    esac
}

# ---- 6. aesmd 再起動 --------------------------------------------------------
restart_aesmd() {
    log "aesmd サービスを有効化・再起動"
    sudo systemctl enable aesmd >/dev/null 2>&1 || true
    sudo systemctl restart aesmd || warn "aesmd の再起動に失敗（後述の診断を確認）"
}

# ---- 診断 -------------------------------------------------------------------
check_env() {
    log "環境診断"
    local ok=1

    if ls /dev/sgx_enclave >/dev/null 2>&1 || ls /dev/sgx/enclave >/dev/null 2>&1; then
        echo "  [ok]   SGX デバイス: $(ls /dev/sgx* /dev/sgx/* 2>/dev/null | tr '\n' ' ')"
    else
        echo "  [NG]   /dev/sgx* が見つかりません（BIOS で SGX 有効化、またはカーネル 5.11+ を確認）"; ok=0
    fi

    if [ -f "$SGX_SDK_DIR/environment" ]; then
        echo "  [ok]   SGXSDK: $SGX_SDK_DIR"
    else
        echo "  [NG]   SGXSDK が $SGX_SDK_DIR にありません"; ok=0
    fi

    if ldconfig -p 2>/dev/null | grep -q libsgx_dcap_ql; then
        echo "  [ok]   libsgx_dcap_ql 検出"
    else
        echo "  [NG]   libsgx_dcap_ql が見つかりません"; ok=0
    fi

    if ldconfig -p 2>/dev/null | grep -q dcap_quoteprov; then
        echo "  [ok]   libdcap_quoteprov (QPL) 検出"
    else
        echo "  [NG]   libdcap_quoteprov (QPL) が見つかりません"; ok=0
    fi

    if [ -f /etc/sgx_default_qcnl.conf ]; then
        echo "  [ok]   /etc/sgx_default_qcnl.conf 配置済み"
    else
        echo "  [NG]   /etc/sgx_default_qcnl.conf がありません"; ok=0
    fi

    if systemctl is-active --quiet aesmd; then
        echo "  [ok]   aesmd 稼働中"
    else
        echo "  [NG]   aesmd が稼働していません (systemctl status aesmd で確認)"; ok=0
    fi

    echo
    if [ "$ok" = 1 ]; then
        log "診断 OK。'source $SGX_SDK_DIR/environment && make run' で quote.dat を生成できます"
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
    install_sgx_packages
    install_sdk
    configure_qcnl
    restart_aesmd
    echo
    check_env || true
    echo
    log "完了。次のセッションでは 'source $SGX_SDK_DIR/environment' を忘れずに。"
}

main "$@"

######## Arm CCA Attestation Token 取得サンプル用 Makefile ########
# SGX/TDX のサンプルと違い、CCA は実機が無いため QEMU(TCG) 上に RME スタックを
# 丸ごとビルドする。重い処理は setup.sh に委譲し、ここはその薄いラッパ。
#
#   make setup      … 一括構築（前提パッケージ + ソース取得 + ビルド）。数十GB・長時間
#   make prereqs    … apt 前提パッケージのみ（sudo 必須）
#   make fetch      … repo init + sync のみ
#   make build      … make toolchains + make のみ（fetch 済み前提）
#   make check-env  … 構築状況の診断のみ
#   make run        … QEMU を起動（4 コンソール + make run-only）。手動操作用。README の手順へ
#   make token      … ★ヘッドレス自動取得。QEMU 起動→Host/Realm 自動ログイン→
#                      cca-workload-attestation report→cca-token.cbor 保存まで無人で実行
#   make clean      … サンプルが生成した中間物（base64/cbor）を削除（ビルド木は消さない）
#   make distclean  … ワークスペース($CCA_WORKSPACE)ごと削除（要注意・数十GB）
#
# 上書き可能: CCA_WORKSPACE（既定 $HOME/cca）, JOBS（既定 nproc）
# 詳細は README.md と同梱の cca-ra-doc.pdf を参照。

CCA_WORKSPACE ?= $(HOME)/cca

.PHONY: setup prereqs fetch build check-env run token clean distclean

setup:
	@./setup.sh

prereqs:
	@sudo ./setup.sh --prereqs

fetch:
	@./setup.sh --fetch

build:
	@./setup.sh --build

check-env:
	@./setup.sh --check

## QEMU を起動する。soc_term.py の 4 コンソール接続は build/Makefile の run-only が行う。
## 起動後の操作（Host ログイン → Realm 起動 → token 取得）は README を参照。
run:
	@test -d "$(CCA_WORKSPACE)/build" || { echo "build/ が無い。先に 'make setup' を実行"; exit 1; }
	@echo "==> $(CCA_WORKSPACE)/build で 'make run-only' を実行します"
	@$(MAKE) -C "$(CCA_WORKSPACE)/build" run-only

## ヘッドレス自動取得: QEMU 起動から token 保存まで無人実行（TCG 二段ブートで十数分〜）。
## 進捗は $(CCA_WORKSPACE)/realm-run/{qemu,fw,host,realm}.log を tail で追える。
token:
	@test -x "$(CCA_WORKSPACE)/qemu/build/qemu-system-aarch64" || { echo "QEMU 未ビルド。先に 'make setup'"; exit 1; }
	@CCA_WORKSPACE="$(CCA_WORKSPACE)" python3 drive-realm.py --out "$(CURDIR)/cca-token.cbor"
	@echo "saved: $(CURDIR)/cca-token.cbor （TEE Anchor の --token に渡す入力）"

clean:
	@rm -f cca-token.cbor cca-token.b64 cca-token*.cbor
	@echo "cleaned: cca-token.cbor / cca-token.b64"

distclean:
	@echo "WARNING: $(CCA_WORKSPACE) を削除します（数十GB・再ビルドが必要）"
	@rm -rf "$(CCA_WORKSPACE)"
	@echo "removed: $(CCA_WORKSPACE)"

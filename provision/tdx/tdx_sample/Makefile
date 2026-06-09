######## 最小 TD Quote 取得サンプル用 Makefile ########
# SGX サンプル (provision/sgx/sgx_sample) と異なり TDX は Enclave 署名も
# edger8r も不要。libtdx_attest に対して 1 ファイルをリンクするだけ。
#
#   make            … get_quote をビルド
#   make run        … ビルドして ./get_quote を実行し quote.dat を生成（要 sudo: 下記注記）
#   make setup      … 環境構築（Intel APT リポジトリ + libtdx-attest 等）を一括実行（sudo 必要）
#   make check-env  … 構築済み環境の診断のみ（インストールはしない）
#   make clean      … 生成物を削除
#
# 注: /dev/tdx_guest へのアクセスに root が要る環境が多い。Quote 取得が
#     Permission denied になる場合は `sudo ./get_quote` で実行すること。

CC       ?= gcc
CFLAGS   ?= -O2 -Wall -Wextra -std=c11
LDLIBS   := -ltdx_attest

TARGET   := get_quote
SRC      := get_quote.c

.PHONY: all run setup check-env clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
	@echo "built: $(TARGET)"

run: all
	@./$(TARGET)

## 環境構築（Intel APT リポジトリ方式）を一括実行。sudo が必要。
setup:
	@./setup.sh

## 構築済み環境の診断のみ（インストールはしない）。
check-env:
	@./setup.sh --check

clean:
	@rm -f $(TARGET) quote.dat
	@echo "cleaned: $(TARGET) quote.dat"

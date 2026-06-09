# tee-anchor 本体ビルド (Phase 1)。
#
# 依存:
#   - C++17 コンパイラ (g++ 11+ / clang++ 14+)
#   - OpenSSL 3.x の開発ヘッダ・ライブラリ (libcrypto)
#
# 使い方:
#   make            … tee-anchor をビルド
#   make clean      … 生成物を削除

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra
INCLUDES := -Icommon -Ica -Iprovision -Iprovision/sgx -Iprovision/tdx -Iprovision/sev-snp -Iverify -I.
LDLIBS   := -lcrypto

BIN      := tee-anchor

SRCS := \
    tee_anchor.cpp \
    ca/ca_init.cpp \
    ca/revocation_db.cpp \
    ca/revoke.cpp \
    ca/crl_issue.cpp \
    binding/chip_id_binding.cpp \
    provision/provision.cpp \
    provision/sgx/sgx_provision.cpp \
    provision/tdx/tdx_provision.cpp \
    provision/sev-snp/snp_provision.cpp \
    verify/verify.cpp

HDRS := \
    common/openssl_raii.hpp \
    common/error.hpp \
    common/io.hpp \
    common/hex.hpp \
    common/pki_util.hpp \
    ca/ca_init.hpp \
    ca/revocation_db.hpp \
    ca/revoke.hpp \
    ca/crl_issue.hpp \
    binding/chip_id_binding.hpp \
    provision/provision.hpp \
    provision/sgx/sgx_provision.hpp \
    provision/sgx/intel_sgx_root_pubkey.hpp \
    provision/tdx/tdx_provision.hpp \
    provision/sev-snp/snp_provision.hpp \
    provision/sev-snp/amd_ark_pubkeys.hpp \
    verify/verify.hpp

.PHONY: all clean
all: $(BIN)

$(BIN): $(SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SRCS) -o $@ $(LDLIBS)

# ビルドにより生成される成果物を削除する。
#   - $(BIN)        : メインバイナリ
#   - 各サブディレクトリの *.o : 現状の単発コンパイルでは出ないが、
#                                将来 per-file 分割ビルドへ移行した際の保険
# 注: provision/sgx/sgx_sample は独立した Makefile を持つので、必要なら
#     `make -C provision/sgx/sgx_sample clean` を別途実行する。
clean:
	@rm -f $(BIN)
	@rm -f tee_anchor.o \
	       ca/*.o binding/*.o common/*.o \
	       provision/*.o provision/sgx/*.o provision/tdx/*.o provision/sev-snp/*.o \
	       verify/*.o
	@echo "cleaned: $(BIN) (+ any stray .o under our source tree)"

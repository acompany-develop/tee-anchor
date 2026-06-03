######## 最小 Quote 取得サンプル用 Makefile ########
# Humane-RAFW-MAA の Makefile から、本サンプルに不要な設定
# (Client_App / switchless / 鍵交換 / 2段階署名) を削ってある。
#
#   make            … enclave 署名 + app をビルド
#   make run        … ビルドして ./sample_app を実行し quote.dat を生成
#   make clean      … 生成物を削除
#
# 既定は DEBUG enclave + 1段階署名（鍵はなければ自動生成）。
# PCK 証明書 / Chip ID は enclave のデバッグ状態に依存しないため、
# DEBUG enclave の Quote でも TEE Anchor の provision/verify に使える。

SGX_SDK   ?= /opt/intel/sgxsdk
SGX_MODE  ?= HW
SGX_ARCH  ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS  := -m32
	SGX_LIBRARY_PATH   := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R        := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS  := -m64
	SGX_LIBRARY_PATH   := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R        := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name  := sgx_urts_sim
	Trts_Library_Name  := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Urts_Library_Name  := sgx_urts
	Trts_Library_Name  := sgx_trts
	Service_Library_Name := sgx_tservice
endif


######## App (Untrusted) ########
App_Include_Paths := -IApp -IEnclave -I$(SGX_SDK)/include
App_Cpp_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths) \
                 -std=c++17 -DNDEBUG -UEDEBUG -UDEBUG
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) \
                  -l$(Urts_Library_Name) -lsgx_dcap_ql -ldcap_quoteprov -lpthread
App_Name := sample_app


######## Enclave (Trusted) ########
Enclave_Include_Paths := -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc \
                         -I$(SGX_SDK)/include/libcxx
Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie \
                   -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++17 -nostdinc++
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs \
	-nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0

Enclave_Name        := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Key         := Enclave/private_key.pem
Enclave_Config_File := Enclave/Enclave.config.xml


.PHONY: all run clean setup check-env
all: $(App_Name) $(Signed_Enclave_Name)

run: all
	@./$(App_Name)

## 環境構築（Ubuntu 24.04 / Intel APT リポジトリ方式）を一括実行。sudo が必要。
setup:
	@./setup.sh

## 構築済み環境の診断のみ（インストールはしない）。
check-env:
	@./setup.sh --check


## ---- Untrusted edge & app ----
App/sample_enclave_u.c: $(SGX_EDGER8R) Enclave/sample_enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/sample_enclave.edl \
		--search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

App/sample_enclave_u.o: App/sample_enclave_u.c
	@$(CC) $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes -IApp -I$(SGX_SDK)/include -c $< -o $@
	@echo "CC   <=  $<"

App/sample_app.o: App/sample_app.cpp App/sample_enclave_u.c
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): App/sample_enclave_u.o App/sample_app.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


## ---- Trusted edge & enclave ----
Enclave/sample_enclave_t.c: $(SGX_EDGER8R) Enclave/sample_enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted sample_enclave.edl \
		--search-path . --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/sample_enclave_t.o: Enclave/sample_enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/sample_enclave.o: Enclave/sample_enclave.cpp Enclave/sample_enclave_t.c
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): Enclave/sample_enclave_t.o Enclave/sample_enclave.o
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

## 署名鍵が無ければ生成（SGX 要件: RSA 3072bit, 指数 3）
$(Enclave_Key):
	@openssl genrsa -out $@ -3 3072
	@echo "GEN  =>  $@"

## 1段階署名（DEBUG/PRERELEASE/通常 RELEASE で可。HW_RELEASE 量産時のみ別途2段階署名が必要）
$(Signed_Enclave_Name): $(Enclave_Name) $(Enclave_Key)
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Key) \
		-enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"


clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) \
		App/sample_app.o App/sample_enclave_u.* \
		Enclave/sample_enclave.o Enclave/sample_enclave_t.* \
		quote.dat

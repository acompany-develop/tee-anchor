/*
 * sample_app.cpp
 *
 * TEE Anchor 付属の最小 Quote 取得サンプル（Untrusted 側）。
 *
 * 役割は一つだけ:
 *   QE3 の target info を取得 -> Enclave に REPORT を作らせる
 *   -> DCAP の sgx_qe_get_quote で Quote を生成 -> ファイルに保存。
 *
 * 生成された quote.dat は TEE Anchor の provision / verify にそのまま渡せる。
 * Quote 末尾の Certification Data に PCK 証明書チェーンが入っているので、
 * 実行後に表示される cert key type が 5 (PCK_CERT_CHAIN) であることを確認すること。
 * 5 以外だと PCK 証明書を取り出せず、provision/verify が使えない。
 *
 * Humane-RAFW-MAA の server_app.cpp の Quote 生成部分を、
 * RA セッション・鍵交換・HTTP・JSON を全て剥がして抽出したもの。
 */
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include <sgx_urts.h>
#include <sgx_report.h>
#include <sgx_dcap_ql_wrapper.h>
#include <sgx_quote_3.h>

#include "sample_enclave_u.h"

#define ENCLAVE_FILE "enclave.signed.so"

/* Enclave をロードする */
static int initialize_enclave(sgx_enclave_id_t &eid)
{
    sgx_status_t st = sgx_create_enclave(
        ENCLAVE_FILE, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);

    if (st != SGX_SUCCESS) {
        std::fprintf(stderr,
            "[error] sgx_create_enclave failed: 0x%04x\n", st);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    /* 第1引数: 出力先（省略時 quote.dat）
     * 第2引数: REPORT data に載せる任意文字列（省略時 0 埋め、最大 64 バイト） */
    const char *out_path = (argc > 1) ? argv[1] : "quote.dat";

    sgx_report_data_t report_data = {0};
    if (argc > 2) {
        size_t n = std::strlen(argv[2]);
        if (n > sizeof(report_data.d)) n = sizeof(report_data.d);
        std::memcpy(report_data.d, argv[2], n);
    }

    /* 1. Enclave ロード */
    sgx_enclave_id_t eid = 0;
    if (initialize_enclave(eid) != 0) return 1;

    /* 2. QE3 の target info を取得 */
    sgx_target_info_t qe_target_info;
    std::memset(&qe_target_info, 0, sizeof(qe_target_info));

    quote3_error_t qe = sgx_qe_get_target_info(&qe_target_info);
    if (qe != SGX_QL_SUCCESS) {
        std::fprintf(stderr,
            "[error] sgx_qe_get_target_info failed: 0x%04x\n", qe);
        sgx_destroy_enclave(eid);
        return 1;
    }

    /* 3. Enclave に REPORT を生成させる */
    sgx_report_t report;
    std::memset(&report, 0, sizeof(report));
    sgx_status_t retval = SGX_SUCCESS;

    sgx_status_t st = ecall_create_report(
        eid, &retval, &qe_target_info, &report_data, &report);

    if (st != SGX_SUCCESS || retval != SGX_SUCCESS) {
        std::fprintf(stderr,
            "[error] ecall_create_report failed: ecall=0x%04x retval=0x%04x\n",
            st, retval);
        sgx_destroy_enclave(eid);
        return 1;
    }

    /* 4. Quote サイズ算出 -> Quote 生成 */
    uint32_t quote_size = 0;
    qe = sgx_qe_get_quote_size(&quote_size);
    if (qe != SGX_QL_SUCCESS) {
        std::fprintf(stderr,
            "[error] sgx_qe_get_quote_size failed: 0x%04x\n", qe);
        sgx_destroy_enclave(eid);
        return 1;
    }

    std::vector<uint8_t> quote(quote_size);
    qe = sgx_qe_get_quote(&report, quote_size, quote.data());
    if (qe != SGX_QL_SUCCESS) {
        std::fprintf(stderr,
            "[error] sgx_qe_get_quote failed: 0x%04x\n", qe);
        sgx_destroy_enclave(eid);
        return 1;
    }

    /* 5. Certification Data の種別を確認（PCK 抽出可否のチェック） */
    const sgx_quote3_t *q = reinterpret_cast<const sgx_quote3_t *>(quote.data());
    const sgx_ql_ecdsa_sig_data_t *sig =
        reinterpret_cast<const sgx_ql_ecdsa_sig_data_t *>(q->signature_data);
    const sgx_ql_auth_data_t *auth =
        reinterpret_cast<const sgx_ql_auth_data_t *>(sig->auth_certification_data);
    const sgx_ql_certification_data_t *cert =
        reinterpret_cast<const sgx_ql_certification_data_t *>(
            sig->auth_certification_data + sizeof(*auth) + auth->size);

    /* 6. ファイル出力 */
    std::ofstream ofs(out_path, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        std::fprintf(stderr, "[error] cannot open output file: %s\n", out_path);
        sgx_destroy_enclave(eid);
        return 1;
    }
    ofs.write(reinterpret_cast<const char *>(quote.data()), quote_size);
    ofs.close();

    std::printf("Quote written: %s (%u bytes)\n", out_path, quote_size);
    std::printf("cert key type : %u%s\n",
        cert->cert_key_type,
        cert->cert_key_type == 5
            ? " (PCK_CERT_CHAIN: OK, PCK cert is embedded)"
            : " (WARNING: not 5; PCK cert chain is NOT embedded)");

    sgx_destroy_enclave(eid);
    return 0;
}

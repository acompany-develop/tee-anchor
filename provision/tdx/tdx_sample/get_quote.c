/*
 * get_quote.c
 *
 * TEE Anchor 付属の最小 TD Quote 取得サンプル。
 *
 * 役割は一つだけ:
 *   libtdx_attest の tdx_att_get_quote() で TD Quote を 1 個取得し、ファイルに保存する。
 *
 * SGX サンプル (provision/sgx/sgx_sample) と異なり、TDX では Enclave も
 * Quoting Enclave の同居も不要。ゲスト (TD) 内の libtdx_attest が
 *   TDREPORT 生成 (/dev/tdx_guest ioctl)
 *     -> vsock 経由でホストの QGS (Quote Generation Service) に転送
 *       -> TD Quoting Enclave が Quote を生成
 * という流れを内部で隠蔽してくれる。呼び出し側は report_data を渡すだけ。
 *
 * 生成された quote.dat はそのまま TEE Anchor の provision / verify (TDX 経路) に
 * 渡せる。SGX の PCK 証明書チェーンと同様、TD Quote 末尾の Certification Data に
 * PCK 証明書が埋め込まれており、そこから Chip ID (PPID) を抽出する想定。
 *
 * Humane-RAFW-TDX の attester/tdx_wrapper.c の Quote 生成部分を、
 * Python FFI / HTTP / 鍵交換を剥がしてスタンドアロン CLI にしたもの。
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "tdx_attest.h"

/* TD Quote ヘッダ (Quote v4) の先頭フィールドを覗くための最小オフセット。
 * 仕様: Intel TDX DCAP Quoting Library, Quote 4.0 形式。
 *   offset 0x00  version      (uint16, LE)  TDX では 4
 *   offset 0x02  att_key_type (uint16, LE)  2 = ECDSA-P256
 *   offset 0x04  tee_type     (uint32, LE)  0x00000081 = TDX, 0x00000000 = SGX
 */
static uint16_t rd_u16le(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd_u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int main(int argc, char **argv)
{
    /* 第1引数: 出力先（省略時 quote.dat）
     * 第2引数: REPORT data に載せる任意文字列（省略時 0 埋め、最大 64 バイト） */
    const char *out_path = (argc > 1) ? argv[1] : "quote.dat";

    tdx_report_data_t report_data;
    memset(&report_data, 0, sizeof(report_data));
    if (argc > 2) {
        size_t n = strlen(argv[2]);
        if (n > sizeof(report_data.d)) n = sizeof(report_data.d);
        memcpy(report_data.d, argv[2], n);
    }

    /* TD Quote 取得。att_key_id_list は NULL=既定鍵に任せる。 */
    tdx_uuid_t selected_key_id;
    memset(&selected_key_id, 0, sizeof(selected_key_id));
    uint8_t *quote_buf = NULL;
    uint32_t quote_size = 0;

    tdx_attest_error_t ret = tdx_att_get_quote(
        &report_data,
        NULL,            /* att_key_id_list */
        0,               /* list_size       */
        &selected_key_id,
        &quote_buf,
        &quote_size,
        0);              /* flags           */

    if (ret != TDX_ATTEST_SUCCESS) {
        fprintf(stderr,
            "[error] tdx_att_get_quote failed: 0x%04x\n", ret);
        fprintf(stderr,
            "        /dev/tdx_guest が存在し、ホスト側 QGS に vsock 到達可能か確認してください。\n");
        return 1;
    }

    if (!quote_buf || quote_size == 0) {
        fprintf(stderr, "[error] empty quote returned\n");
        tdx_att_free_quote(quote_buf);
        return 1;
    }

    /* ファイル出力 */
    FILE *fp = fopen(out_path, "wb");
    if (!fp) {
        fprintf(stderr, "[error] cannot open output file: %s\n", out_path);
        tdx_att_free_quote(quote_buf);
        return 1;
    }
    size_t written = fwrite(quote_buf, 1, quote_size, fp);
    fclose(fp);
    if (written != quote_size) {
        fprintf(stderr, "[error] short write to %s (%zu/%u)\n",
                out_path, written, quote_size);
        tdx_att_free_quote(quote_buf);
        return 1;
    }

    printf("TD Quote written: %s (%u bytes)\n", out_path, quote_size);

    /* ヘッダの version / tee_type を表示（Humane-RAFW-TDX の参照ツールと同じ確認）。
     * 期待値: version=4, tee_type=0x00000081 (TDX)。 */
    if (quote_size >= 8) {
        uint16_t version  = rd_u16le(quote_buf + 0x00);
        uint16_t key_type = rd_u16le(quote_buf + 0x02);
        uint32_t tee_type = rd_u32le(quote_buf + 0x04);
        printf("  quote version : %u%s\n", version,
               version == 4 ? "" : " (WARNING: expected 4 for TDX)");
        printf("  att key type  : %u%s\n", key_type,
               key_type == 2 ? " (ECDSA-P256)" : "");
        printf("  tee type      : 0x%08x%s\n", tee_type,
               tee_type == 0x00000081 ? " (TDX: OK)"
                                       : " (WARNING: not TDX)");
    }
    printf("\nこの quote.dat を TEE Anchor の provision/verify (--tee-type tdx) に渡せます。\n");

    tdx_att_free_quote(quote_buf);
    return 0;
}

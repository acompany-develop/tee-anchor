/*
 * sample_enclave.cpp
 *
 * 最小 Quote 取得サンプルの Trusted 側。
 * QE3 を target とした REPORT を生成して返すだけ。
 *
 * Chip ID（PPID 由来）は Quote 内の PCK 証明書側に入るため、
 * report_data の中身は TEE Anchor の binding 検証には影響しない。
 * ここでは呼び出し側が渡した 64 バイトをそのまま REPORT に載せる。
 */
#include "sample_enclave_t.h"
#include <sgx_utils.h>

sgx_status_t ecall_create_report(const sgx_target_info_t *qe_target_info,
    const sgx_report_data_t *report_data, sgx_report_t *report)
{
    return sgx_create_report(qe_target_info, report_data, report);
}

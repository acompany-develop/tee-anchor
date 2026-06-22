# ベースはHumane-RAFW-TDX内の以下のスクリプト。ライセンスもそちらを継承し準拠する。
# https://github.com/acompany-develop/Humane-RAFW-TDX/blob/main/relying-party/rp_client.py
import os
import ssl
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
import base64
import hashlib
import tomllib
import ctypes
import datetime
import sys
import atexit
import time
import json
import statistics
import subprocess
import contextlib
from enum import IntEnum
from qvl_wrapper import verify_quote, QvlVerifyOutPy

SETTINGS_PATH = "./settings.toml"
PINNED_CERT_PATH = "./pinned_attester_cert.pem"

# ---------------------------------------------------------------------------
# ベンチマーク設定 (環境変数で上書き可)
#   従来 RA (verify_quote + appraise_quote) を「TEE Anchor を呼ばない場合(A)」、
#   その直後に subprocess で tee-anchor verify --tee-type tdx を回す場合を
#   「呼ぶ場合(B)」とし、do_RA 内で両者をループ計測して差分を出す。さらに
#   ORG_CRL を指定すると tee-anchor verify --crl 付き(C: 失効照合込み)も同時に
#   計測し、CRL 処理の純追加コスト(C-B)を得る。SGX 版 client_app.cpp と同思想。
#   hyperfine が使えない (RA が live attester への通信を伴う) ため、Quote を
#   一度だけ取得し、検証段だけをループする in-process 計測とする。
# ---------------------------------------------------------------------------
BENCH_ENABLED = os.environ.get("BENCH", "0") == "1"
BENCH_RUNS    = int(os.environ.get("BENCH_RUNS", "50"))
BENCH_WARMUP  = int(os.environ.get("BENCH_WARMUP", "5"))
BENCH_OUT     = os.environ.get("BENCH_OUT", "./bench_tdx.json")

# tee-anchor (TDX verify) 呼び出しに必要なパス
QUOTE_OUT_PATH = os.environ.get("QUOTE_OUT", "./quote.dat")
TEE_ANCHOR_BIN = os.environ.get(
    "TEE_ANCHOR", os.path.expanduser("~/Develop/tee-anchor/tee-anchor"))
ORG_CERT_PATH  = os.environ.get("ORG_CERT", "./tdx_endorsement.crt")
ORG_CA_PATH    = os.environ.get("ORG_CA", "./ca.crt")
# 組織 CRL (失効リスト)。指定時のみ --crl 付き verify (失効照合) シナリオ C も計測する。
# tee-anchor verify は CRL に endorsement が載っていれば exit 24 を返す。
# SGX 版 (benchmark/sgx/verify/client_app.cpp) の ORG_CRL と同じ役割。
ORG_CRL_PATH   = os.environ.get("ORG_CRL", "")

# 計測ループ中は appraise_quote の大量の print を抑止する捨て先
_DEVNULL = open(os.devnull, "w")
atexit.register(_DEVNULL.close)

ROOT_KEY_ID_SIZE = 48
PLATFORM_INSTANCE_ID_SIZE = 16
MAX_SA_LIST_SIZE = 320

class QvResult(IntEnum):
    OK = 0x00000000
    
    CONFIG_NEEDED = 0x0000A001
    OUT_OF_DATE = 0x0000A002
    OUT_OF_DATE_AND_CONFIG_NEEDED = 0x0000A003
    
    INVALID_SIGNATURE = 0x0000A004
    REVOKED = 0x0000A005
    UNSPECIFIED = 0x0000A006

    SW_HAEDENING_NEEDED = 0x0000A007
    CONFIG_AND_SW_HARDENING_NEEDED = 0x0000A008

    TD_RELAUNCH_ADVISED = 0x0000A009
    TD_RELAUNCH_ADVISED_CONFIG_NEEDED = 0x0000A00A

class PckCertFlag(IntEnum):
    FALSE = 0
    TRUE = 1
    UNDEFINED = 2

class SupplementalData(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_int32),
        ("earliest_issue_date", ctypes.c_int64),
        ("latest_issue_date", ctypes.c_int64),
        ("earliest_expiration_date", ctypes.c_int64),
        ("tcb_level_date_tag", ctypes.c_int64),
        ("pck_crl_num", ctypes.c_uint32),
        ("root_ca_crl_num", ctypes.c_uint32),
        ("tcb_eval_ref_num", ctypes.c_uint32),
        ("root_key_id", ctypes.c_uint8 * ROOT_KEY_ID_SIZE),
        ("pck_ppid", ctypes.c_uint8 * 16),
        ("tcb_cpusvn", ctypes.c_uint8 * 16),
        ("tcb_pce_isvsvn", ctypes.c_uint16),
        ("pce_id", ctypes.c_uint16),
        ("tee_type", ctypes.c_uint32),
        ("sgx_type", ctypes.c_uint8),
        ("platform_instance_id", ctypes.c_uint8 * PLATFORM_INSTANCE_ID_SIZE),

        ("dynamic_platform", ctypes.c_uint32),
        ("cached_keys", ctypes.c_uint32),
        ("smt_enabled", ctypes.c_uint32),

        ("sa_list", ctypes.c_char * MAX_SA_LIST_SIZE),
        ("qe_iden_earliest_issue_date", ctypes.c_int64),
        ("qe_iden_latest_issue_date", ctypes.c_int64),
        ("qe_iden_earliest_expiration_date", ctypes.c_int64),
        ("qe_iden_tcb_level_date_tag", ctypes.c_int64),
        ("qe_iden_tcb_eval_ref_num", ctypes.c_uint32),
        ("qe_iden_status", ctypes.c_uint32),
    ]


def cleanup_pinned_cert():
    try:
        if os.path.exists(PINNED_CERT_PATH):
            os.remove(PINNED_CERT_PATH)
            print(f"[cleanup] Removed {PINNED_CERT_PATH}")
    except Exception as e:
        print(f"[cleanup] Failed to remove pinned cert: {e}")

atexit.register(cleanup_pinned_cert)


def resolve_attester_url() -> str:
    with open(SETTINGS_PATH, "rb") as f:
        settings = tomllib.load(f)
    url = settings["network"]["attester_url"]

    if not url.endswith("/"):
        url += "/"
    return url


def generate_nonce() -> bytes:
    return os.urandom(32)


def request_quote():
    nonce = generate_nonce()
    payload = {"nonce": base64.b64encode(nonce).decode()}

    res = requests.post(
        ATTESTER_URL + "attest",
        json = payload,
        verify = False,
        timeout = 60
    )

    res.raise_for_status()
    data = res.json()

    quote_hex = data["quote"]
    tls_cert_pem = data["tls_cert"].encode()
    cert_hash_hex = data["cert_hash"]
    tdeventlog = data["tdeventlog"].encode("utf-8")
    ima_log = data["ima_log"].encode("utf-8")
    nonce_log_hash_hex = data["nonce_log_hash"]

    calc = hashlib.sha256(tls_cert_pem).hexdigest()

    if calc != cert_hash_hex:
        raise RuntimeError("cert_hash mismatch")

    print("Obtained TD Quote successfully.")
    print(f"Quote size: {len(quote_hex)//2} bytes")
    print(f"Nonce sent: {nonce.hex()}")

    with open(PINNED_CERT_PATH, "wb") as f:
        f.write(tls_cert_pem)

    print(f"Saved pinned certificate: {PINNED_CERT_PATH}")

    tdeventlog_path = "./tdeventlog.txt"
    with open(tdeventlog_path, "wb") as f:
        f.write(tdeventlog)

    print(f"Saved TD Event Log: {tdeventlog_path}")

    ima_log_path = "./ima_runtime_measurements.txt"
    with open(ima_log_path, "wb") as f:
        f.write(ima_log)

    print(f"Saved IMA runtime measurements: {ima_log_path}")


    return {
        "nonce": nonce,
        "quote": quote_hex,
        "tls_cert": tls_cert_pem,
        "cert_hash": cert_hash_hex,
        "tdeventlog": tdeventlog,
        "ima_log": ima_log,
        "nonce_log_hash": bytes.fromhex(nonce_log_hash_hex),
    }


# Supplemental Dataを専用構造体に変換
def parse_supplemental_data(supp_bytes: bytes) -> SupplementalData:
    if len(supp_bytes) < ctypes.sizeof(SupplementalData):
        raise RuntimeError("Supplemental Data size is too small.")

    return SupplementalData.from_buffer_copy(supp_bytes)


# 測定値比較関数
def check_measurement(name: str, actual: bytes, expected: bytes | None):
    if expected is None:
        print(f"{name} skipped (reference is none).")
        return

    if actual != expected:
        raise RuntimeError(
            f"Measurement mismatch: {name}\n"
            f"  expected: {expected.hex()}\n"
            f"  actual  : {actual.hex()}"
        )

    print(f"{name} matched.")


def fmt_time(t: int) -> str:
    if t == 0:
        return "N/A"
    return datetime.datetime.fromtimestamp(t, tz=datetime.timezone.utc).isoformat()


def parse_sa_list(sa_bytes: bytes) -> list[str]:
    s = sa_bytes.split(b'\x00', 1)[0].decode("ascii", errors="ignore").strip()

    if not s:
        return []

    return [item.strip() for item in s.split(",") if item.strip()]


# QuoteとSupplemental Dataの内容物検証
def appraise_quote(quote: bytes, qvl_out: QvlVerifyOutPy,
    cert_hash_hex: str, nonce: bytes, tdeventlog: bytes, ima_log: bytes, nonce_log_hash: bytes) -> bool:
    
    quote_size = len(quote)

    if quote_size < 8:
        print(f"Invalid Quote size: {quote_size}")
        return False

    quote_version = int.from_bytes(quote[0:2], byteorder="little", signed=False)
    tee_type = int.from_bytes(quote[4:8], byteorder="little", signed=False)

    # Quoteバージョンの確認
    print(f"\nQuote version -> {quote_version}\n")
    
    if quote_version == 4:
        report_base = 48
    elif quote_version == 5:
        report_base = 54
    else:
        print("Invalid Quote type.")
        return False

    if quote_size < report_base + 564:
        print(f"Invalid Quote size: {quote_size}")
        return False

    # TEEタイプの確認
    print(f"TEE type -> {tee_type:#x}\n")

    if tee_type != 0x81:
        print("The Quote is not for TDX.")
        return False

    # Quoteタイプの識別。sgx_quote_4.hの場合は無条件に-1とする
    if quote_version == 5:
        quote_type = int.from_bytes(quote[48:50], byteorder='little')
    else:
        quote_type = -1

    # 各種測定値等のパース
    tee_tcb_svn = quote[report_base:report_base+16]
    mr_seam = quote[report_base+16:report_base+16+48]
    mrsigner_seam = quote[report_base+64:report_base+64+48]
    seam_attributes = quote[report_base+112:report_base+112+8]
    td_attributes = quote[report_base+120:report_base+120+8]
    xfam = quote[report_base+128:report_base+128+8]
    mr_td = quote[report_base+136:report_base+136+48]
    mr_config_id = quote[report_base+184:report_base+184+48]
    mr_owner = quote[report_base+232:report_base+232+48]
    mr_owner_config = quote[report_base+280:report_base+280+48]
    rtmr_0 = quote[report_base+328:report_base+328+48]
    rtmr_1 = quote[report_base+328+48:report_base+328+48*2]
    rtmr_2 = quote[report_base+328+48*2:report_base+328+48*3]
    rtmr_3 = quote[report_base+328+48*3:report_base+328+48*4]
    report_data = quote[report_base+520:report_base+520+64]

    if quote_type == 3 or quote_type == 4:
        tee_tcb_svn2 = quote[report_base+584:report_base+584+16]
        mr_servicetd = quote[report_base+600:report_base+600+48]

    if quote_type == 4:
        vmid = int.from_bytes(quote[report_base+648:report_base+649], byteorder='little')
        td_id = quote[report_base+649:report_base+681]
        devinfo = quote[report_base+681:report_base+729]
        init_server_td_hash = quote[report_base+729:report_base+729+48]
        init_server_td_attr = quote[report_base+777:report_base+777+8]
        init_cpu_svn = quote[report_base+785:report_base+785+16]
        init_tee_tcb_svn = quote[report_base+801:report_base+801+16]
        init_tee_fmspc = quote[report_base+817:report_base+817+12]
        curr_server_td_hash = quote[report_base+829:report_base+829+48]
        curr_server_td_attr = quote[report_base+877:report_base+877+8]



    print("\n[Report Body in TD Quote]")
    print(f"{'MRSEAM':<21}-> {mr_seam.hex()}\n")
    print(f"{'MRSIGNERSEAM':<21}-> {mrsigner_seam.hex()}\n")
    print(f"{'SEAM Attributes':<21}-> {seam_attributes.hex()}\n")
    print(f"{'TD Attributes':<21}-> {td_attributes.hex()}\n")
    print(f"{'XFAM':<21}-> {xfam.hex()}\n")
    print(f"{'MRTD':<21}-> {mr_td.hex()}\n")
    print(f"{'MRCONFIGID':<21}-> {mr_config_id.hex()}\n")
    print(f"{'MROWNER':<21}-> {mr_owner.hex()}\n")
    print(f"{'MROWNERCONFIG':<21}-> {mr_owner_config.hex()}\n")
    print(f"{'RTMR[0]':<21}-> {rtmr_0.hex()}\n")
    print(f"{'RTMR[1]':<21}-> {rtmr_1.hex()}\n")
    print(f"{'RTMR[2]':<21}-> {rtmr_2.hex()}\n")
    print(f"{'RTMR[3]':<21}-> {rtmr_3.hex()}\n")
    print(f"{'Report Data':<21}-> {report_data.hex()}\n")

    if quote_type == 3 or quote_type == 4:
        print(f"{'TEE_TCB_SVN2':<21}-> {tee_tcb_svn2.hex()}\n")
        print(f"{'MR_SERVICETD':<21}-> {mr_servicetd.hex()}\n")

    if quote_type == 4:
        print(f"{'VMID':<21}-> {vmid}\n")
        print(f"{'TD_ID':<21}-> {td_id.hex()}\n")
        print(f"{'DEVINFO':<21}-> {devinfo.hex()}\n")
        print(f"{'INIT_SERVER_TD_HASH':<21}-> {init_server_td_hash.hex()}\n")
        print(f"{'INIT_SERVER_TD_ATTR':<21}-> {init_server_td_attr.hex()}\n")
        print(f"{'INIT_CPU_SVN':<21}-> {init_cpu_svn.hex()}\n")
        print(f"{'INIT_TEE_TCB_SVN':<21}-> {init_tee_tcb_svn.hex()}\n")
        print(f"{'INIT_TEE_FMSPC':<21}-> {init_tee_fmspc.hex()}\n")
        print(f"{'CURR_SERVER_TD_HASH':<21}-> {curr_server_td_hash.hex()}\n")
        print(f"{'CURR_SERVER_TD_ATTR':<21}-> {curr_server_td_attr.hex()}\n")

    td_attr_int = int.from_bytes(td_attributes, byteorder="little", signed=False)
    is_debug_enabled = bool(td_attr_int & 0x1)

    print(f"Is TD in Debug mode? -> {is_debug_enabled}\n")
    print(f"Collateral expiration status -> {qvl_out.collateral_expiration_status}\n")

    # リファレンス値の読み込み
    with open("reference.toml", "rb") as f:
        ref = tomllib.load(f)

    def load_ref(key: str) -> bytes | None:
        val = ref["measurements"][key]
        if val == "none":
            return None
        return bytes.fromhex(val)

    ref_mr_td = load_ref("mr_td")
    ref_mr_seam = load_ref("mr_seam")
    ref_mrsigner_seam = load_ref("mrsigner_seam")

    ref_rtmr0 = load_ref("rtmr0")
    ref_rtmr1 = load_ref("rtmr1")
    ref_rtmr2 = load_ref("rtmr2")
    ref_rtmr3 = load_ref("rtmr3")

    ref_mr_config_id = load_ref("mr_config_id")
    ref_mr_owner = load_ref("mr_owner")
    ref_mr_owner_config = load_ref("mr_owner_config")

    allow_debug = ref["policy"]["allow_debug"]
    allow_collateral_expiration = ref["policy"]["allow_collateral_expiration"]
    allow_cfg_needed = ref["policy"]["allow_configuration_needed"]
    allow_sw_hardening = ref["policy"]["allow_sw_hardening_needed"]
    allow_out_of_date = ref["policy"]["allow_out_of_date"]
    allow_td_relaunch_advised = ref["policy"]["allow_td_relaunch_advised"]
    allow_smt_enabled = ref["policy"]["allow_smt_enabled"]
    req_tcb_eval_ds_num = ref["policy"]["required_tcb_eval_ds_num"]
    allowed_sa_list = ref["policy"]["allowed_sa_list"]

    # RAステータスチェック
    ra_status = QvResult(qvl_out.quote_verification_result)
    print(f"RA Status: {ra_status.name} ({ra_status.value:#x})")

    if ra_status == QvResult.OK:
        print("Quote is trusted.")

    if (ra_status == QvResult.INVALID_SIGNATURE
        or ra_status == QvResult.REVOKED
        or ra_status == QvResult.UNSPECIFIED):
        print("Quote is untrusted.")
        return False

    if (ra_status == QvResult.CONFIG_NEEDED
        or ra_status == QvResult.OUT_OF_DATE_AND_CONFIG_NEEDED
        or ra_status == QvResult.CONFIG_AND_SW_HARDENING_NEEDED
        or ra_status == QvResult.TD_RELAUNCH_ADVISED_CONFIG_NEEDED):
        if allow_cfg_needed:
            print("CONFIGURATION_NEEDED is allowed by user's policy.")
        else:
            print("CONFIGURATION_NEEDED is disallowed by user's policy.")
            return False

    if (ra_status == QvResult.SW_HAEDENING_NEEDED
        or ra_status == QvResult.CONFIG_AND_SW_HARDENING_NEEDED):
        if allow_sw_hardening:
            print("SW_HARDENING_NEEDED is allowed by user's policy.")
        else:
            print("SW_HARDENING_NEEDED is disallowed by user's policy.")
            return False

    if (ra_status == QvResult.OUT_OF_DATE
        or ra_status == QvResult.OUT_OF_DATE_AND_CONFIG_NEEDED):
        if allow_out_of_date:
            print("OUT_OF_DATE is allowed by user's policy.")
        else:
            print("OUT_OF_DATE is disallowed by user's policy.")
            return False

    if (ra_status == QvResult.TD_RELAUNCH_ADVISED
        or ra_status == QvResult.TD_RELAUNCH_ADVISED_CONFIG_NEEDED):
        if allow_td_relaunch_advised:
            print("TD_RELAUNCH_ADVISED is allowed by user's policy.")
        else:
            print("TD_RELAUNCH_ADVISED is disallowed by user's policy.")
            return False
    

    # 測定値チェック
    try:
        check_measurement("MRTD", mr_td, ref_mr_td)
        check_measurement("MRSEAM", mr_seam, ref_mr_seam)
        check_measurement("MRSIGNERSEAM", mrsigner_seam, ref_mrsigner_seam)
        check_measurement("RTMR[0]", rtmr_0, ref_rtmr0)
        check_measurement("RTMR[1]", rtmr_1, ref_rtmr1)
        check_measurement("RTMR[2]", rtmr_2, ref_rtmr2)
        check_measurement("RTMR[3]", rtmr_3, ref_rtmr3)
        check_measurement("MRCONFIGID", mr_config_id, ref_mr_config_id)
        check_measurement("MROWNER", mr_owner, ref_mr_owner)
        check_measurement("MROWNERCONFIG", mr_owner_config, ref_mr_owner_config)

    except RuntimeError as e:
        print(e)
        return False

    # ポリシチェック
    if not allow_debug and is_debug_enabled:
        print("TD Debug mode is disallowed by user's policy.")
        return False
    
    elif allow_debug and is_debug_enabled:
        print("TD Debug mode is allowed by user's policy.")

    else:
        print("TD is not in Debug mode.")

    
    if not allow_collateral_expiration and qvl_out.collateral_expiration_status > 0:
        print("Collateral has expired, disallowed by user's policy.")
        return False

    elif allow_collateral_expiration and qvl_out.collateral_expiration_status > 0:
        print("Collateral has expired, allowed by user's policy.")

    else:
        print("Collateral hasn't expired.")

    
    # Supplemental Dataの処理
    if qvl_out.supplemental_data != None:
        try:
            supp = parse_supplemental_data(qvl_out.supplemental_data)
        except RuntimeError as e:
            print(e)
            return False
    else:
        print("Cannot obtain Supplemental Data.")
        return False

    print(len(qvl_out.supplemental_data))
    print(ctypes.sizeof(SupplementalData))


    # Supplemental Dataの内容表示
    print("\n[Supplemental Data]")
    major = supp.version & 0xFFFF
    minor = (supp.version >> 16) & 0xFFFF

    W = 33
    print(f"{'version':<{W}}-> {major}.{minor}")
    print(f"{'earliest_issue_date':<{W}}-> {fmt_time(supp.earliest_issue_date)}")
    print(f"{'latest_issue_date':<{W}}-> {fmt_time(supp.latest_issue_date)}")
    print(f"{'earliest_expiration_date':<{W}}-> {fmt_time(supp.earliest_expiration_date)}")
    print(f"{'tcb_level_date_tag':<{W}}-> {fmt_time(supp.tcb_level_date_tag)}")
    print(f"{'pck_crl_num':<{W}}-> {supp.pck_crl_num}")
    print(f"{'root_ca_crl_num':<{W}}-> {supp.root_ca_crl_num}")
    print(f"{'tcb_eval_ref_num':<{W}}-> {supp.tcb_eval_ref_num}")
    print(f"{'root_key_id':<{W}}-> {bytes(supp.root_key_id).hex()}")
    print(f"{'pck_ppid':<{W}}-> {bytes(supp.pck_ppid).hex()}")
    print(f"{'tcb_cpusvn':<{W}}-> {bytes(supp.tcb_cpusvn).hex()}")
    print(f"{'tcb_pce_isvsvn':<{W}}-> {supp.tcb_pce_isvsvn}")
    print(f"{'pce_id':<{W}}-> {supp.pce_id}")
    print(f"{'tee_type':<{W}}-> {hex(supp.tee_type)}")
    print(f"{'sgx_type':<{W}}-> {supp.sgx_type}")
    print(f"{'platform_instance_id':<{W}}-> {bytes(supp.platform_instance_id).hex()}")
    print(f"{'dynamic_platform':<{W}}-> {PckCertFlag(supp.dynamic_platform).name}")
    print(f"{'cached_keys':<{W}}-> {PckCertFlag(supp.cached_keys).name}")
    print(f"{'smt_enabled':<{W}}-> {PckCertFlag(supp.smt_enabled).name}")

    sa = supp.sa_list.rstrip(b"\x00").decode(errors="ignore")
    print(f"{'sa_list':<{W}}-> {sa if sa else '(empty)'}")

    print(f"{'qe_iden_earliest_issue_date':<{W}}-> {fmt_time(supp.qe_iden_earliest_issue_date)}")
    print(f"{'qe_iden_latest_issue_date':<{W}}-> {fmt_time(supp.qe_iden_latest_issue_date)}")
    print(f"{'qe_iden_earliest_expiration_date':<{W}}-> {fmt_time(supp.qe_iden_earliest_expiration_date)}")
    print(f"{'qe_iden_tcb_level_date_tag':<{W}}-> {fmt_time(supp.qe_iden_tcb_level_date_tag)}")
    print(f"{'qe_iden_tcb_eval_ref_num':<{W}}-> {supp.qe_iden_tcb_eval_ref_num}")

    try:
        print(f"{'qe_iden_status':<{W}}-> {QvResult(supp.qe_iden_status).name}")
    except ValueError:
        print(f"{'qe_iden_status':<{W}}-> UNKNOWN ({hex(supp.qe_iden_status)})")

    print("")


    # ポリシチェック
    if supp.smt_enabled == PckCertFlag.TRUE:
        if not allow_smt_enabled:
            print("SMT is enabled, disallowed by user's policy.")
            return False
        else:
            print("SMT is enabled, allowed by user's policy.")
    
    elif supp.smt_enabled == PckCertFlag.FALSE:
        print("SMT is disabled.")
    
    else:
        print("Unknown SMT status flag.")
        return False

    
    if supp.tcb_eval_ref_num < req_tcb_eval_ds_num:
        print(f"Insufficient TCB Evaluation Dataset Number. Expected: {req_tcb_eval_ds_num} or more")
        return False
    else:
        print("Sufficient TCB Evaluation Dataset Number.")

    
    sa_actual = parse_sa_list(supp.sa_list)
    
    if not sa_actual:
        print("No Security Advisories reported.")

    else:
        disallowed = set(sa_actual) - set(allowed_sa_list)

        if disallowed:
            print("Disallowed Security Advisories detected:\n"
                + "\n".join(f"  - {sa}" for sa in disallowed))
            return False

        print("All Security Advisories are allowed by user's policy.")

    # Report Dataの検証。前半32バイトは動的TLS証明書のSHA256ハッシュ値、
    # 後半32バイトはSHA256(nonce + tdeventlog + ima_log)
    cert_hash = bytes.fromhex(cert_hash_hex)

    if len(cert_hash) != 32:
        print("cert_hash must be 32 bytes.")
        return False

    expected_nonce_log_hash = hashlib.sha256(nonce + tdeventlog + ima_log).digest()

    expected_report_data = cert_hash + expected_nonce_log_hash

    if report_data != expected_report_data:
        print(
            "Report Data mismatch\n"
            f" expected: {expected_report_data.hex()}\n"
            f" actual  : {report_data.hex()}"
        )
        return False

    else:
        print("Report Data matched.")

    return True


class PinnedCertAdapter(HTTPAdapter):
    """ピンニング済み証明書でサーバを検証するが、SAN/ホスト名検証は行わない。
    証明書の真正性はTDX QuoteのReport Data (SHA256(cert)) で保証済みのため、
    SANによるホスト名検証は冗長である。"""

    def __init__(self, ca_cert_path, **kwargs):
        self.ca_cert_path = ca_cert_path
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(self.ca_cert_path)
        kwargs["ssl_context"] = ctx
        # server_hostnameにIPが渡るとurllib3内部でSANマッチが走るため、
        # assert_hostnameをFalseにしてurllib3レベルのチェックも無効化する
        kwargs["assert_hostname"] = False
        return super().init_poolmanager(*args, **kwargs)


def call_add_api(a: int, b: int) -> int:
    if not os.path.exists(PINNED_CERT_PATH):
        raise RuntimeError("Pinned certificate not found. RA must be done first.")

    session = requests.Session()
    session.mount("https://", PinnedCertAdapter(PINNED_CERT_PATH))

    res = session.post(
        ATTESTER_URL + "add",
        json={"a": a, "b": b},
        timeout=10,
    )

    res.raise_for_status()

    data = res.json()
    return data["result"]



# ---------------------------------------------------------------------------
# ベンチマーク用ヘルパ
# ---------------------------------------------------------------------------
def _conventional_ra_once(quote_bytes: bytes, result: dict) -> None:
    """従来 RA 1 回分 (ベンダー検証 + appraise)。print は計測ノイズになるので抑止。"""
    with contextlib.redirect_stdout(_DEVNULL):
        vr = verify_quote(quote_bytes)
        appraise_quote(
            quote_bytes, vr, result["cert_hash"], result["nonce"],
            result["tdeventlog"], result["ima_log"], result["nonce_log_hash"])


def _tee_anchor_once(quote_path: str, with_crl: bool = False) -> int:
    """TEE Anchor (TDX verify) を subprocess で 1 回。出力は捨て、exit code を返す。
    with_crl=True のときは --crl <ORG_CRL> を付け、失効リスト照合も行わせる
    (失効済みなら exit 24)。SGX 版 tee_anchor_verify_once(with_crl) と同思想。"""
    cmd = [TEE_ANCHOR_BIN, "verify", "--tee-type", "tdx",
           "--quote", quote_path, "--org-cert", ORG_CERT_PATH, "--org-ca", ORG_CA_PATH]
    if with_crl:
        cmd += ["--crl", ORG_CRL_PATH]
    return subprocess.run(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    ).returncode


def _stats_ms(samples_ns: list[int]) -> dict:
    ms = [s / 1e6 for s in samples_ns]
    return {
        "runs": len(ms),
        "mean_ms": statistics.fmean(ms),
        "stdev_ms": statistics.pstdev(ms) if len(ms) > 1 else 0.0,
        "min_ms": min(ms),
        "max_ms": max(ms),
        "median_ms": statistics.median(ms),
    }


def _fmt(s: dict) -> str:
    return (f"mean {s['mean_ms']:.3f} ± {s['stdev_ms']:.3f} ms  "
            f"(min {s['min_ms']:.3f}, median {s['median_ms']:.3f}, max {s['max_ms']:.3f}, n={s['runs']})")


def run_benchmark(result: dict, quote_bytes: bytes) -> None:
    """do_RA で 1 回信頼判定した後に呼ぶ。
    A: 従来 RA のみ (TEE Anchor を呼ばない)
    B: 従来 RA + tee-anchor subprocess (CRL なし)
    C: 従来 RA + tee-anchor subprocess (--crl 付き)  ※ ORG_CRL 指定時のみ
    を各反復で計測し、差分 (= TEE Anchor 追加コスト / CRL 追加コスト) を出す。
    SGX 版 (benchmark/sgx/verify/client_app.cpp) の A/B/C と同思想。"""
    # tee-anchor へ渡す Quote をファイル化
    with open(QUOTE_OUT_PATH, "wb") as f:
        f.write(quote_bytes)

    anchor_ok = all(os.path.exists(p) for p in (TEE_ANCHOR_BIN, ORG_CERT_PATH, ORG_CA_PATH))
    # CRL シナリオ(C): ORG_CRL が指定され、かつ anchor 自体が可能なときのみ有効
    crl_ok = anchor_ok and bool(ORG_CRL_PATH) and os.path.exists(ORG_CRL_PATH)

    print("\n" + "=" * 70)
    print("[bench] TDX RA benchmark")
    print(f"[bench] runs={BENCH_RUNS} warmup={BENCH_WARMUP}")
    print(f"[bench] quote      : {QUOTE_OUT_PATH} ({len(quote_bytes)} bytes)")
    if anchor_ok:
        print(f"[bench] tee-anchor : {TEE_ANCHOR_BIN}")
        print(f"[bench] org-cert   : {ORG_CERT_PATH}")
        print(f"[bench] org-ca     : {ORG_CA_PATH}")
        rc = _tee_anchor_once(QUOTE_OUT_PATH)
        print(f"[bench] sanity: tee-anchor verify (no CRL) exit code = {rc}"
              + ("  (OK)" if rc == 0 else "  (WARNING: 非ゼロ。endorsement/CA/quote の整合を確認)"))
        if crl_ok:
            print(f"[bench] org-crl    : {ORG_CRL_PATH}")
            rc_crl = _tee_anchor_once(QUOTE_OUT_PATH, with_crl=True)
            print(f"[bench] sanity: tee-anchor verify (--crl) exit code = {rc_crl}"
                  + ("  (OK: 未失効)" if rc_crl == 0
                     else "  (失効検出: exit 24)" if rc_crl == 24
                     else "  (WARNING: 想定外の exit code)"))
        elif ORG_CRL_PATH:
            print(f"[bench] WARNING: ORG_CRL 指定 ({ORG_CRL_PATH}) が見つからないため"
                  " CRL シナリオ(C)はスキップします。")
    else:
        missing = [p for p in (TEE_ANCHOR_BIN, ORG_CERT_PATH, ORG_CA_PATH) if not os.path.exists(p)]
        print(f"[bench] WARNING: 次が無いため従来 RA のみ計測します: {missing}")
        print("[bench]   tee-anchor provision --tee-type tdx ... で endorsement を発行し、")
        print("[bench]   ORG_CERT= / ORG_CA= を指定して再実行してください。")

    # ウォームアップ (DCAP collateral キャッシュ温め / linker / CPU クロック)
    for _ in range(BENCH_WARMUP):
        _conventional_ra_once(quote_bytes, result)
        if anchor_ok:
            _tee_anchor_once(QUOTE_OUT_PATH)
        if crl_ok:
            _tee_anchor_once(QUOTE_OUT_PATH, with_crl=True)

    conv_ns, anchor_ns, total_ns = [], [], []
    anchor_crl_ns, total_crl_ns = [], []
    for i in range(BENCH_RUNS):
        t0 = time.perf_counter_ns()
        _conventional_ra_once(quote_bytes, result)
        t1 = time.perf_counter_ns()
        conv_ns.append(t1 - t0)

        if anchor_ok:
            t2 = time.perf_counter_ns()
            _tee_anchor_once(QUOTE_OUT_PATH)
            t3 = time.perf_counter_ns()
            anchor_ns.append(t3 - t2)
            total_ns.append((t1 - t0) + (t3 - t2))

        if crl_ok:
            t4 = time.perf_counter_ns()
            _tee_anchor_once(QUOTE_OUT_PATH, with_crl=True)
            t5 = time.perf_counter_ns()
            anchor_crl_ns.append(t5 - t4)
            total_crl_ns.append((t1 - t0) + (t5 - t4))

        if (i + 1) % 10 == 0:
            print(f"[bench]   {i + 1}/{BENCH_RUNS} done")

    conv = _stats_ms(conv_ns)
    report = {"runs": BENCH_RUNS, "warmup": BENCH_WARMUP,
              "quote_bytes": len(quote_bytes),
              "tee_anchor_available": anchor_ok,
              "crl_scenario": crl_ok,
              "conventional_ra": conv}

    print("\n" + "-" * 70)
    print(f"[bench] A. 従来 RA のみ (verify_quote + appraise)        : {_fmt(conv)}")
    if anchor_ok:
        anchor = _stats_ms(anchor_ns)
        total = _stats_ms(total_ns)
        report["tee_anchor_subprocess"] = anchor
        report["ra_plus_anchor"] = total
        overhead_pct = 100.0 * anchor["mean_ms"] / conv["mean_ms"]
        report["overhead_pct_of_conventional"] = overhead_pct
        print(f"[bench] B. 従来 RA + TEE Anchor (CRL なし)             : {_fmt(total)}")
        print(f"[bench] Δ  TEE Anchor 追加コスト (B-A = subprocess 分)  : {_fmt(anchor)}")
        print(f"[bench] 追加コストは従来 RA の {overhead_pct:.1f}% (= TEE Anchor を足す相対オーバーヘッド)")

        if crl_ok:
            anchor_crl = _stats_ms(anchor_crl_ns)
            total_crl = _stats_ms(total_crl_ns)
            crl_extra_ms = anchor_crl["mean_ms"] - anchor["mean_ms"]  # C-B: CRL の純追加コスト
            report["tee_anchor_subprocess_crl"] = anchor_crl
            report["ra_plus_anchor_crl"] = total_crl
            report["crl_extra_ms"] = crl_extra_ms
            print(f"[bench] C. 従来 RA + TEE Anchor (--crl 付き)           : {_fmt(total_crl)}")
            print(f"[bench] Δ' TEE Anchor(+CRL) 追加コスト (C-A)           : {_fmt(anchor_crl)}")
            print(f"[bench] CRL 処理の純追加コスト (C-B = anchor 差)       : {crl_extra_ms:.3f} ms")
    print("-" * 70)

    with open(BENCH_OUT, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[bench] 結果を {BENCH_OUT} に保存しました。")
    if anchor_ok:
        print("[bench] 注意: Δ は subprocess 起動を含む「TEE Anchor を後付けした実コスト」。")
        print("[bench]       tee-anchor の TDX verify は PCK チェーンを quote 内証明書で")
        print("[bench]       オフライン検証するため、追加のネットワーク往復は発生しない。")
        if crl_ok:
            print("[bench]       --crl 照合も組織 CRL ファイルをローカル参照するのみで、")
            print("[bench]       やはりネットワーク往復は発生しない (C-B はその純コスト)。")


def do_RA():
    result = request_quote()
    quote_bytes = bytes.fromhex(result["quote"])

    verify_result = verify_quote(quote_bytes)

    if verify_result.wrapper_ret != 0:
        print(f"Failed to verify Quote. wrapper_ret: {verify_result.wrapper_ret:#x}")
    if verify_result.dcap_ret != 0:
        print(f"Failed to verify Quote. dcap_ret: {verify_result.dcap_ret:#x}")

    status = appraise_quote(quote_bytes, verify_result,
        result["cert_hash"], result["nonce"], result["tdeventlog"], result["ima_log"], result["nonce_log_hash"])

    if status:
        print("\nAttester is Trusted. Accept RA.")
    else:
        print("\nAttester is Untrusted. Reject RA.")
        sys.exit()

    # ベンチマークモード: 信頼判定後にループ計測を実行して終了 (対話表示はスキップ)
    if BENCH_ENABLED:
        run_benchmark(result, quote_bytes)
        return

    if input("\nDisplay TD Event Log? (y/N): ").strip().lower() == "y":
        print("\n[TD Event Log]")
        print(result["tdeventlog"].decode("utf-8", errors="replace"))

    if input("Display IMA runtime measurements? (y/N): ").strip().lower() == "y":
        print("\n[IMA Runtime Measurements]")
        print(result["ima_log"].decode("utf-8", errors="replace"))


if __name__ == "__main__":
    ATTESTER_URL = resolve_attester_url()
    print(f"[config] ATTESTER_URL = {ATTESTER_URL}")

    do_RA()

    # ベンチマーク時はサンプル秘密計算をスキップ
    if not BENCH_ENABLED:
        # サンプル秘密計算リクエスト関数
        x, y = 100, 200
        r = call_add_api(x, y)
        print(f"Secure Add Result: {x} + {y} = {r}")
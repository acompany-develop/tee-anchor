#!/usr/bin/env python3
# drive-realm.py — ヘッドレスで CCA Attestation Token を 1 個取得する自動ドライバ。
#
# GUI 端末や手動操作なしに、QEMU(RME) を起動 → 外側 Host Linux にログイン →
# nested Realm guest を起動 → Realm にログイン → cca-workload-attestation report →
# 生成された cca-token.cbor を base64 でコンソール経由に吸い出してホストに保存する。
#
# 設計上の要点（ハマりどころ）:
#   1. QEMU は serial を SERVER モード（QEMU がリッスン）で開き、本スクリプトが
#      クライアント接続する。`make run-only` 経由だと内部の `nc -z` ポート探査が
#      先に接続してしまい QEMU の本接続を取り逃すため、QEMU を直接起動している。
#   2. QEMU/TCG はシングルスレッド。どれか 1 つの serial ソケットのバッファが
#      埋まると VM 全体が停止するので、4 コンソール全てを常時 drain する。
#   3. base64 回収のマーカーはシェル変数で組み立て、コマンドのエコーバック行に
#      マーカー文字列が出ないようにする（出ると抽出が誤爆する）。
#
# 使い方:
#   python3 drive-realm.py            # 既定: $HOME/cca を使い ./cca-token.cbor に保存
#   CCA_WORKSPACE=/path python3 drive-realm.py --out /tmp/cca-token.cbor
#
# 注意: TCG の二段ブート（外側 Host + nested Realm）なので完了まで十数分〜数十分。
import os, socket, subprocess, sys, time, select, re, base64, threading, argparse

WS = os.environ.get("CCA_WORKSPACE", os.path.expanduser("~/cca"))
BINDIR = os.path.join(WS, "out/bin")
QEMU = os.path.join(WS, "qemu/build/qemu-system-aarch64")
ROOTFS = os.path.join(WS, "out-br/images/rootfs.ext4")
PORTS = {54320: "fw", 54321: "secure", 54322: "host", 54323: "realm"}

def qemu_cmd():
    return [QEMU,
        "-M","virt,virtualization=on,secure=on,gic-version=3",
        "-M","acpi=off","-cpu","max,x-rme=on,sme=off,pauth-impdef=on",
        "-m","3G","-smp","4","-nographic",
        "-bios","flash.bin","-kernel","Image",
        "-drive",f"format=raw,if=none,file={ROOTFS},id=hd0",
        "-device","virtio-blk-pci,drive=hd0","-nodefaults",
        "-serial","tcp:localhost:54320,server=on,wait=off",
        "-serial","tcp:localhost:54321,server=on,wait=off",
        "-chardev","socket,id=hvc0,host=localhost,port=54322,server=on,wait=off",
        "-device","virtio-serial-device","-device","virtconsole,chardev=hvc0",
        "-chardev","socket,id=hvc1,host=localhost,port=54323,server=on,wait=off",
        "-device","virtio-serial-device","-device","virtconsole,chardev=hvc1",
        "-append","root=/dev/vda earlycon console=hvc0 nokaslr",
        "-device","virtio-net-pci,netdev=net0","-netdev","user,id=net0",
        "-device","virtio-9p-device,fsdev=shr0,mount_tag=shr0",
        "-fsdev","local,security_model=none,path=../../,id=shr0"]

# 外側 Host で叩く nested Realm 起動コマンド（stdin/stdout を /dev/hvc1=port54323 に接続）。
REALM_CMD = (
    "qemu-system-aarch64 -M confidential-guest-support=rme0 "
    "-object rme-guest,id=rme0,measurement-algorithm=sha512 -nodefaults "
    "-chardev stdio,mux=on,id=virtiocon0,signal=off "
    "-device virtio-serial-pci -device virtconsole,chardev=virtiocon0 "
    "-mon chardev=virtiocon0,mode=readline "
    "-kernel /mnt/out/bin/Image -initrd /mnt/out-br/images/rootfs.cpio "
    "-device virtio-net-pci,netdev=net0,romfile= -netdev user,id=net0 "
    "-cpu host -M virt -enable-kvm -M gic-version=3,its=on "
    "-smp 2 -m 512M -nographic -append console=hvc0 < /dev/hvc1 >/dev/hvc1"
)

LOGDIR = os.path.join(WS, "realm-run")

class Console:
    def __init__(self, port, name):
        self.port=port; self.name=name; self.conn=None
        self.buf=""; self.lock=threading.Lock(); self.stop=False
        self.log=open(os.path.join(LOGDIR,f"{name}.log"),"wb",buffering=0)
    def connect(self, timeout=60):
        deadline=time.time()+timeout
        while time.time()<deadline:
            try:
                self.conn=socket.create_connection(("127.0.0.1",self.port),timeout=5)
                threading.Thread(target=self._reader,daemon=True).start(); return True
            except OSError: time.sleep(0.5)
        return False
    def _reader(self):
        self.conn.setblocking(False)
        while not self.stop:
            try:
                r,_,_=select.select([self.conn],[],[],0.3)
                if not r: continue
                data=self.conn.recv(65536)
                if not data: break
                self.log.write(data)
                with self.lock: self.buf+=data.decode("utf-8","replace")
            except (BlockingIOError,OSError): break
    def send(self,s):
        self.conn.sendall(s.encode()); self.log.write(b"\n<<SENT>> "+s.encode()+b"\n")
    def expect(self,pattern,timeout,label=""):
        rx=re.compile(pattern); deadline=time.time()+timeout
        while time.time()<deadline:
            with self.lock:
                if rx.search(self.buf): return True
            time.sleep(0.5)
        with self.lock: tail=self.buf[-1200:]
        print(f"[TIMEOUT] {self.name}: waiting for {label or pattern!r}",flush=True)
        print(f"--- last 1200 chars of {self.name} ---\n{tail}\n---",flush=True)
        return False
    def snapshot(self):
        with self.lock: return self.buf

# マーカー間の base64 を取り出す。マーカーはコマンドのエコー行には現れない前提
# （シェル変数で組み立てるため）。本文も base64 文字種の行だけ採用する。
def extract_b64(text, begin, end):
    m=re.search(re.escape(begin)+r"(.*?)"+re.escape(end), text, re.S)
    if not m: return None
    body=m.group(1)
    return "".join(re.findall(r"[A-Za-z0-9+/=]+", body))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(os.getcwd(),"cca-token.cbor"))
    ap.add_argument("--host-timeout", type=int, default=1800)
    ap.add_argument("--realm-timeout", type=int, default=1500)
    args=ap.parse_args()
    os.makedirs(LOGDIR, exist_ok=True)

    for p in (QEMU, os.path.join(BINDIR,"flash.bin"), os.path.join(BINDIR,"Image"), ROOTFS):
        if not os.path.exists(p):
            print(f"[!] missing build artifact: {p}\n    先に `make setup` でビルドしてください。"); return 1

    qemu=subprocess.Popen(qemu_cmd(),cwd=BINDIR,
        stdout=open(os.path.join(LOGDIR,"qemu.log"),"wb"),
        stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL)
    print("[*] qemu pid",qemu.pid,flush=True)
    cons={p:Console(p,n) for p,n in PORTS.items()}
    for p,c in cons.items():
        if not c.connect(60): print(f"[!] {c.name}({p}) connect failed"); return 1
        print(f"[*] {c.name}({p}) connected",flush=True)
    host,realm,fw=cons[54322],cons[54323],cons[54320]

    if not host.expect(r"login:",args.host_timeout,"host login"): return 2
    host.send("root\n")
    if not host.expect(r"# ",120,"host shell"): return 2
    print("[*] host shell ready; launching realm",flush=True)

    host.send(REALM_CMD+"\n")
    if not realm.expect(r"login:",args.realm_timeout,"realm login"): return 3
    realm.send("root\n")
    if not realm.expect(r"# ",180,"realm shell"): return 3
    print("[*] realm shell ready; requesting token",flush=True)

    realm.send("cca-workload-attestation report\n")
    realm.expect(r"CCA token saved|cca-token\.cbor|# ",240,"report done")
    time.sleep(3)

    # マーカーはシェル変数で組み立てる → コマンドのエコー行には "CCATOKBEG" 等が
    # 出ず、実行結果にだけ現れる（マーカー衝突による誤抽出を防ぐ）。
    with realm.lock: realm.buf=""
    realm.send('M=CCATOK; echo ${M}BEG; base64 cca-token.cbor; echo ${M}END\n')
    if not realm.expect(r"CCATOKEND",180,"base64 block"): return 4
    b64=extract_b64(realm.snapshot(), "CCATOKBEG", "CCATOKEND")
    if not b64: print("[!] no base64 captured"); return 4
    raw=base64.b64decode(b64)
    with open(args.out,"wb") as f: f.write(raw)
    print(f"[OK] wrote {args.out} ({len(raw)} bytes)",flush=True)
    print("[OK] first bytes:",raw[:12].hex(),flush=True)
    return 0

if __name__=="__main__":
    sys.exit(main())

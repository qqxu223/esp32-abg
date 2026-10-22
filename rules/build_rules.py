#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_rules.py — 把域名列表编译成固件能直接吃的规则包。

为什么需要这个脚本，而不是直接把 hosts 文件丢进 flash：
  1. 域名平均 25 字节，244k 条要 6MB。压成 40 位哈希后只要 1.2MB，LittleFS 放得下。
  2. 必须按哈希升序排列，固件才能用 256 桶索引做到"一次 seek 命中"。
  3. 必须剔除"伞域"（如 akamai.net），否则会连带打死大量正常 CDN。

输出格式（v2）：
  magic(4)="ESPR" | version(1)=2 | flags(1) | count(4, LE) | entries(count × 5 字节)

用法：
  python build_rules.py --out ../firmware/data/blocklist.bin
  python build_rules.py --profile ultimate        # light / pro / ultimate / max
  python build_rules.py --check ../firmware/data/blocklist.bin   # 校验已有包
"""

import argparse
import hashlib
import os
import struct
import sys
import urllib.request

MAGIC = b"ESPR"
VERSION = 2
HASH_BYTES = 5
MASK = (1 << (HASH_BYTES * 8)) - 1

# ---------------------------------------------------------------- 规则源
# hagezi 是目前维护最勤的 DNS 拦截列表，分档清晰。
SOURCES = {
    "light": [
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light.txt",
    ],
    "pro": [
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt",
    ],
    "ultimate": [
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.plus.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini.txt",
    ],
    "max": [
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium.txt",
    ],
}

# 国内广告/追踪/统计主域 —— hagezi 对国内覆盖偏弱（umeng.com 只有 1 条），必须手工补
# 这些是"通配父域"，命中即连带子域，实测能砍掉 App 内绝大部分埋点上报
CN_TRACKERS = """
umeng.com umengcloud.com umeng.com.cn uyunadz.com uy.fun
cnzz.com cnzz.net zz.bdstatic.com hm.baidu.com pos.baidu.com
sensorsdata.cn sensorsdata.com growingio.com
talkingdata.com talkingdata.cn
miaozhen.com miaozhen.com.cn adjuz.com
tanx.com alimama.com mmstat.com atanx.alicdn.com
pos.baidu.com cpro.baidu.com mobads.baidu.com
e.qq.com gdt.qq.com pgdt.qq.com adnet.qq.com
pangolin-sdk-toutiao.com pglstatp-toutiao.com bytedance.com
app-measurement.com firebaseinstallations.googleapis.com
appsflyer.com app.adjust.com adjust.com
jiagu.360.cn mads.360.cn
union.360.cn
adview.cn adview.com
youmi.net domob.cn domob.com.cn
inmobi.com inmobi.cn
ironsrc.com unityads.unity3d.com
startapp.com vungle.com chartboost.com
adcolony.com applovin.com
mintegral.com mtgglobals.com
appicad.com
getui.com getui.net igexin.com
jpush.cn jiguang.cn
mob.com mobpush.com
umeng.co
growingio.com
zhugeio.com
beacon.qq.com
pingjs.qq.com
hmcdn.baidu.com
hm.baidu.com
tongji.baidu.com
retcode.qq.com
apm.qq.com
beacon.tingyun.com
one.aliyun.com
arms.aliyun.com
log.aliyun.com
sls.aliyun.com
"""

# 危险伞域：命中会连带打死大量正常服务，必须从规则里剔除
# 这些是从实践里踩出来的坑，不是理论推测
BANNED_SUFFIX = {
    # CDN / 云基础设施，拦了直接"断网"
    "akamai.net", "akamaiedge.net", "akamaitechnologies.com", "edgekey.net", "edgesuite.net",
    "cloudflare.com", "cloudflare.net", "cloudfront.net", "fastly.net", "fastlylb.net",
    "alicdn.com", "aliyuncs.com", "aliyun.com", "aliyuncdn.com", "kunluncn.com",
    "qcloud.com", "myqcloud.com", "tencentcs.com", "tencent-cloud.com",
    "bdstatic.com", "bdimg.com", "bcebos.com", "baidubce.com",
    "gstatic.com", "googleapis.com", "googleusercontent.com", "googlevideo.com",
    "githubusercontent.com", "github.com", "gitlab.com",
    "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "msftconnecttest.com", "msftncsi.com", "windowsupdate.com",
    # 推送/支付/登录 —— 拦了会导致 App 收不到消息、付不了钱
    "apple.com", "icloud.com", "mzstatic.com",
    "google.com", "gmail.com", "youtube.com",
    "microsoft.com", "live.com", "office.com", "outlook.com",
    "weixin.qq.com", "wechat.com", "qq.com", "qpic.cn", "gtimg.cn",
    "alipay.com", "alipayobjects.com", "taobao.com", "tmall.com", "alicdn.com",
    "jd.com", "360buyimg.com",
    "paypal.com", "stripe.com",
    # DNS / NTP / 连通性探测 —— 拦了设备自己会以为断网
    "connectivitycheck.gstatic.com", "connectivitycheck.android.com",
    "ntp.org", "pool.ntp.org", "time.windows.com",
}

# 精确白名单：这些域名一条都不能拦
ALLOW_EXACT = {
    "ocsp.apple.com", "ocsp2.apple.com", "crl.apple.com",
    "time.apple.com", "time1.apple.com", "time2.apple.com",
    "captive.apple.com", "connectivitycheck.gstatic.com",
    "connectivitycheck.platform.hicloud.com",
    "wifi.vivo.com.cn", "connect.rom.miui.com",
    "ntp.aliyun.com", "ntp1.aliyun.com", "time1.cloud.tencent.com",
    "dns.google", "one.one.one.one", "cloudflare-dns.com",
    "push.apple.com", "gateway.push.apple.com",
    "mtalk.google.com", "android.clients.google.com",
    "github.com", "api.github.com", "codeload.github.com",
}

# 模板/单标签等无效项
MIN_LABELS = 2


def fnv40(s: str) -> int:
    h = 0xCBF29CE484222325
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h & MASK


def norm(line: str):
    """解析一行，返回域名或 None。"""
    line = line.strip()
    if not line or line[0] in "#!":
        return None
    # adblock 语法：||domain^
    if line.startswith("||"):
        line = line[2:]
        for sep in ("^", "$", "/"):
            i = line.find(sep)
            if i > 0:
                line = line[:i]
    # hosts 语法：0.0.0.0 domain
    elif line[0].isdigit() or line.startswith("::"):
        parts = line.split()
        if len(parts) < 2:
            return None
        line = parts[1]
    else:
        line = line.split()[0]

    line = line.strip().rstrip(".").lower()
    if line.startswith("*."):
        line = line[2:]
    if not line or "." not in line:
        return None
    if line in ("localhost", "localhost.localdomain", "broadcasthost", "0.0.0.0"):
        return None
    if line.count(".") < MIN_LABELS - 1:
        return None
    # 只接受合法字符
    for c in line:
        if not (c.isalnum() or c in "-_."):
            return None
    return line


def dangerous(d: str) -> bool:
    if d in ALLOW_EXACT:
        return True
    for s in BANNED_SUFFIX:
        if d == s or d.endswith("." + s):
            return True
    return False


def fetch(url: str, timeout=60) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "esp-fleet-rules/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def collect(profile: str, extra_files, offline_dir=None):
    domains = set()

    for url in SOURCES[profile]:
        name = url.rsplit("/", 1)[-1]
        local = os.path.join(offline_dir, name) if offline_dir else None
        try:
            if local and os.path.exists(local):
                with open(local, encoding="utf-8", errors="replace") as f:
                    text = f.read()
                print(f"  [local] {name}  {len(text)/1048576:.1f} MB")
            else:
                print(f"  [http ] {url}")
                text = fetch(url)
                print(f"          {len(text)/1048576:.1f} MB")
        except Exception as e:
            print(f"  [skip ] {url}: {e}")
            continue
        for ln in text.splitlines():
            d = norm(ln)
            if d:
                domains.add(d)

    # 国内追踪主域
    for d in CN_TRACKERS.split():
        d = norm(d)
        if d:
            domains.add(d)

    for path in extra_files or []:
        with open(path, encoding="utf-8", errors="replace") as f:
            for ln in f:
                d = norm(ln)
                if d:
                    domains.add(d)

    before = len(domains)
    domains = {d for d in domains if not dangerous(d)}
    print(f"  剔除危险伞域/白名单：{before - len(domains)} 条")

    return domains


def build(domains):
    hashes = {}
    for d in domains:
        h = fnv40(d)
        # 40 位哈希理论碰撞率：n²/2^41，244k 条约 0.007%，实际几乎不碰撞
        if h in hashes:
            continue
        hashes[h] = d
    items = sorted(hashes.items())
    return items


def write_pack(items, out_path):
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    buf = bytearray()
    buf += MAGIC
    buf += bytes([VERSION, 0])
    buf += struct.pack("<I", len(items))
    for h, _ in items:
        buf += h.to_bytes(HASH_BYTES, "little")
    with open(out_path, "wb") as f:
        f.write(buf)
    return len(buf)


def check_pack(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 10:
        print("包太小，不是合法规则包")
        return False
    magic = data[:4]
    ver = data[4]
    count = struct.unpack("<I", data[6:10])[0]
    actual = (len(data) - 10) // HASH_BYTES
    print(f"magic={magic} ver={ver} count={count} actual={actual} size={len(data)/1048576:.2f}MB")
    ok = magic == MAGIC and ver == VERSION and count == actual
    # 校验升序
    prev = -1
    bad = 0
    for i in range(count):
        o = 10 + i * HASH_BYTES
        v = int.from_bytes(data[o:o + HASH_BYTES], "little")
        if v <= prev:
            bad += 1
        prev = v
    buckets = [0] * 256
    for i in range(count):
        o = 10 + i * HASH_BYTES
        buckets[data[o]] += 1
    print(f"降序/重复异常：{bad}   最大桶：{max(buckets)}   最小桶：{min(buckets)}")
    return ok and bad == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../firmware/data/blocklist.bin")
    ap.add_argument("--profile", default="ultimate", choices=list(SOURCES))
    ap.add_argument("--extra", nargs="*", help="额外域名文件（每行一个）")
    ap.add_argument("--offline", default=".cache", help="本地已下载的源文件目录")
    ap.add_argument("--check", help="只校验已有包")
    ap.add_argument("--sample", nargs="*", help="生成后测试这些域名是否命中")
    args = ap.parse_args()

    if args.check:
        sys.exit(0 if check_pack(args.check) else 1)

    print(f"源档位：{args.profile}")
    domains = collect(args.profile, args.extra, args.offline)
    print(f"去重后域名：{len(domains)}")
    items = build(domains)
    size = write_pack(items, args.out)
    print(f"写出 {args.out}：{len(items)} 条 / {size/1048576:.2f} MB")

    # 自检
    hs = {h for h, _ in items}
    for d in (args.sample or []):
        d = d.lower()
        print(f"  {'HIT ' if fnv40(d) in hs else 'miss'} {d}")

    check_pack(args.out)


if __name__ == "__main__":
    main()

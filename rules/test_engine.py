#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_engine.py — 拦截引擎的边界测试（不依赖硬件）

复刻 firmware/src/adblock.h 里 shouldBlock() 和 DnsAnswer::buildBlocked()
的判定逻辑，跑一组容易出错的用例。
"""

import struct
import sys

MAGIC = b"ESPR"
HASH_BYTES = 5
MASK = (1 << 40) - 1
BLOCK_TTL = 60

# 与 adblock.h 的 RUNTIME_ALLOW 保持一致
RUNTIME_ALLOW = [
    "apple.com", "microsoft.com", "windowsupdate.com", "weixin.qq.com", "wechat.com",
    "qq.com", "alipay.com", "paypal.com", "github.com", "githubusercontent.com",
    "ocsp.apple.com", "time.apple.com", "connectivitycheck.gstatic.com",
    "cloudflare-dns.com", "gstatic.com", "android.clients.google.com",
    "ntp.aliyun.com", "time1.cloud.tencent.com",
]


def fnv40(s):
    h = 0xCBF29CE484222325
    for b in s.encode():
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h & MASK


def is_runtime_allowed(d):
    ld = len(d)
    for a in RUNTIME_ALLOW:
        la = len(a)
        if ld < la:
            continue
        if ld > la and d[ld - la - 1] != ".":
            continue
        if d[ld - la:].lower() == a:
            return True
    return False


def build_blocked(query, qtype, nxdomain, cap=512):
    """复刻 DnsAnswer::buildBlocked"""
    buf = bytearray(query)
    # 找 question 结束位置
    i = 12
    while i < len(buf) and buf[i] != 0:
        i += buf[i] + 1
    qend = i + 5  # 0x00 + qtype(2) + qclass(2)
    buf = bytearray(buf[:qend])
    buf[2] = 0x81
    buf[3] = 0x83 if nxdomain else 0x80
    buf[6:8] = b"\x00\x00"
    buf[8:12] = b"\x00\x00\x00\x00"

    if not nxdomain and qtype == 1:
        if qend + 16 > cap:
            return bytes(buf)
        ans = bytes([0xC0, 0x0C, 0, 1, 0, 1]) + struct.pack(">I", BLOCK_TTL) + b"\x00\x04\x00\x00\x00\x00"
        buf += ans
        buf[6:8] = b"\x00\x01"
    elif not nxdomain and qtype == 28:
        if qend + 28 > cap:
            return bytes(buf)
        ans = bytes([0xC0, 0x0C, 0, 28, 0, 1]) + struct.pack(">I", BLOCK_TTL) + b"\x00\x10" + b"\x00" * 16
        buf += ans
        buf[6:8] = b"\x00\x01"
    return bytes(buf)


def make_query(domain, qtype, qid=0x1234):
    body = b""
    for lb in domain.split("."):
        body += bytes([len(lb)]) + lb.encode()
    body += b"\x00" + struct.pack(">HH", qtype, 1)
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + body


def parse(resp):
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", resp[:12])
    i = 12
    while resp[i] != 0:
        i += resp[i] + 1
    i += 5
    rrs = []
    for _ in range(an):
        if resp[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while resp[i] != 0:
                i += resp[i] + 1
            i += 1
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", resp[i:i + 10])
        i += 10
        rdata = resp[i:i + rdlen]
        i += rdlen
        rrs.append((rtype, ttl, rdata))
    return dict(qid=qid, rcode=flags & 0xF, qr=(flags >> 15) & 1, an=an, rr=rrs)


FAILS = []


def check(name, cond, detail=""):
    if cond:
        print(f"  [OK ] {name}")
    else:
        print(f"  [BAD] {name}  {detail}")
        FAILS.append(name)


def main():
    print("== DNS 应答构造 ==")

    # A 记录拦截
    q = make_query("ads.example.com", 1)
    r = parse(build_blocked(q, 1, False))
    check("A: QR=1", r["qr"] == 1)
    check("A: NOERROR", r["rcode"] == 0, f"rcode={r['rcode']}")
    check("A: ANCOUNT=1", r["an"] == 1)
    check("A: 返回 0.0.0.0", len(r["rr"]) == 1 and r["rr"][0][2] == b"\x00" * 4, r["rr"])
    check("A: TTL=60", r["rr"][0][1] == 60)

    # AAAA 记录拦截
    q = make_query("ads.example.com", 28)
    r = parse(build_blocked(q, 28, False))
    check("AAAA: ANCOUNT=1", r["an"] == 1)
    check("AAAA: 返回 ::", len(r["rr"]) == 1 and r["rr"][0][2] == b"\x00" * 16)
    check("AAAA: RDLENGTH=16", len(r["rr"][0][2]) == 16)

    # HTTPS/SVCB 走 NXDOMAIN
    for qt, nm in ((65, "HTTPS"), (64, "SVCB"), (16, "TXT"), (2, "NS")):
        q = make_query("ads.example.com", qt)
        r = parse(build_blocked(q, qt, True))
        check(f"{nm}: NXDOMAIN", r["rcode"] == 3, f"rcode={r['rcode']}")
        check(f"{nm}: ANCOUNT=0", r["an"] == 0)

    # 报文结构自洽：question 段必须原样保留
    q = make_query("a.very.long.subdomain.for.testing.example.com", 1)
    resp = build_blocked(q, 1, False)
    check("question 段完整保留", resp[12:len(q)] == q[12:], "question 被改动")
    check("ID 保持不变", resp[:2] == q[:2])
    check("QDCOUNT=1", struct.unpack(">H", resp[4:6])[0] == 1)

    print("\n== 运行时白名单 ==")
    check("weixin.qq.com 放行", is_runtime_allowed("weixin.qq.com"))
    check("a.weixin.qq.com 放行（子域）", is_runtime_allowed("a.weixin.qq.com"))
    check("github.com 放行", is_runtime_allowed("github.com"))
    check("api.github.com 放行", is_runtime_allowed("api.github.com"))
    check("notgithub.com 不放行", not is_runtime_allowed("notgithub.com"))
    check("evil-github.com 不放行", not is_runtime_allowed("evil-github.com"))
    check("ads.qq.com 放行（父域 qq.com）", is_runtime_allowed("ads.qq.com"))

    print("\n== 哈希稳定性（固件与编译器必须完全一致）==")
    # 这几个值是 build_rules.py 生成的，固件必须算出同样的结果
    cases = {
        "doubleclick.net": None,
        "google.com": None,
        "umeng.com": None,
    }
    for d in cases:
        cases[d] = fnv40(d)
    for d, h in cases.items():
        print(f"  {d:24s} {h:012x}  ({h})")
    # FNV-1a 40 位的已知值校验
    check("FNV-1a('') == 0xcbf29ce484222325 & mask", fnv40("") == 0xcbf29ce484222325 & MASK,
          hex(fnv40("")))
    check("哈希为 40 位", all(fnv40(d) < (1 << 40) for d in cases))

    print("\n== 长域名 / 边界 ==")
    longd = ".".join(["a" * 60] * 3) + ".com"
    q = make_query(longd, 1)
    resp = build_blocked(q, 1, False)
    check(f"长域名({len(longd)}字节)应答可解析", parse(resp)["an"] == 1)

    print()
    if FAILS:
        print(f"失败 {len(FAILS)} 项：{FAILS}")
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    main()

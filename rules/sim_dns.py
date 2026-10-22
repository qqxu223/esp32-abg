#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sim_dns.py — 模拟完整 DNS 拦截链路，验证"为什么旧方案没用、这套有用"。

它做的事：
  1. 模拟浏览器对一个域名并发发 A / AAAA / HTTPS 三种查询
  2. 按固件逻辑判断是否拦截，并构造真实 DNS 应答报文
  3. 解析应答，检查客户端能不能从里面拿到可用的 IP

判定标准：只要三条查询里任意一条返回了非 0.0.0.0 / 非 :: 的地址，
浏览器就会去连 —— 那就算"拦截失败"。

对照实验：
  --mode a-only   模拟只拦 A 记录的旧实现（预期：拦截失败率高）
  --mode full     模拟本固件（预期：全部拦截成功）
"""

import argparse
import struct
import sys

MAGIC = b"ESPR"
HASH_BYTES = 5
MASK = (1 << 40) - 1
BLOCK_TTL = 60

QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "TXT": 16, "AAAA": 28, "SVCB": 64, "HTTPS": 65}


def fnv40(s):
    h = 0xCBF29CE484222325
    for b in s.encode():
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h & MASK


class Pack:
    def __init__(self, path):
        d = open(path, "rb").read()
        assert d[:4] == MAGIC
        self._d = d
        self.count = struct.unpack("<I", d[6:10])[0]
        self.base = 10
        self.bucket = [0] * 257
        b = 0
        for pos in range(self.count):
            hi = d[self.base + pos * HASH_BYTES + HASH_BYTES - 1]
            while b <= hi and b < 256:
                self.bucket[b] = pos
                b += 1
        while b <= 256:
            self.bucket[b] = self.count
            b += 1

    def get(self, i):
        o = self.base + i * HASH_BYTES
        return int.from_bytes(self._d[o:o + HASH_BYTES], "little")

    def lookup(self, h):
        bk = (h >> ((HASH_BYTES - 1) * 8)) & 0xFF
        a, b = self.bucket[bk], self.bucket[bk + 1]
        while a < b:
            mid = (a + b) // 2
            v = int.from_bytes(self._d[self.base + mid * HASH_BYTES:
                                        self.base + mid * HASH_BYTES + HASH_BYTES], "little")
            if v == h:
                return True
            if v < h:
                a = mid + 1
            else:
                b = mid
        return False

    def should_block(self, domain):
        p = domain
        while True:
            if self.lookup(fnv40(p)):
                return True
            i = p.find(".")
            if i < 0:
                return False
            nxt = p[i + 1:]
            if "." not in nxt:
                return False
            p = nxt


def build_query(qid, domain, qtype):
    """构造一条真实格式的 DNS 查询报文"""
    body = b""
    for label in domain.split("."):
        body += bytes([len(label)]) + label.encode()
    body += b"\x00"
    body += struct.pack(">HH", qtype, 1)
    hdr = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return hdr + body


def build_blocked_reply(query, qtype, mode):
    """复刻 DnsAnswer::buildBlocked"""
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", query[:12])
    # 找 question 结尾
    i = 12
    while query[i] != 0:
        i += query[i] + 1
    qend = i + 1 + 4

    nxdomain = (qtype not in (1, 28))
    if mode == "a-only" and qtype in (28, 64, 65):
        return None  # 旧实现：非 A 查询原样转发（这里视为拿到真实地址）

    newflags = 0x8180 | (0x0003 if nxdomain else 0)
    out = struct.pack(">HHHHHH", qid, newflags, 1, 0, 0, 0) + query[12:qend]

    if not nxdomain and qtype == 1:
        out += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, BLOCK_TTL, 4) + b"\x00\x00\x00\x00"
        out = out[:6] + struct.pack(">H", 1) + out[8:]
    elif not nxdomain and qtype == 28:
        out += b"\xc0\x0c" + struct.pack(">HHIH", 28, 1, BLOCK_TTL, 16) + b"\x00" * 16
        out = out[:6] + struct.pack(">H", 1) + out[8:]
    return out


def parse_answer_ip(resp):
    """从应答里提取客户端能用的地址。返回 None 表示"拿不到地址"。"""
    if resp is None:
        return "REAL"  # 原样转发 = 拿到真实地址
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", resp[:12])
    rcode = flags & 0x000F
    if rcode == 3:  # NXDOMAIN
        return None
    if an == 0:
        return None  # NODATA
    # 解析 answer 段
    i = 12
    while resp[i] != 0:
        i += resp[i] + 1
    i += 5
    rr = resp[i:]
    if len(rr) < 12:
        return None
    rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", rr[2:12])
    rdata = rr[12:12 + rdlen]
    if rtype == 1 and rdlen == 4:
        ip = ".".join(str(b) for b in rdata)
        return None if ip == "0.0.0.0" else ip
    if rtype == 28 and rdlen == 16:
        return None if rdata == b"\x00" * 16 else "::x"
    return None


def test_domain(pk, domain, mode):
    """模拟浏览器并发查 A / AAAA / HTTPS"""
    blocked = pk.should_block(domain)
    results = []
    for name in ("A", "AAAA", "HTTPS"):
        qt = QTYPE[name]
        q = build_query(0x1234, domain, qt)
        if blocked:
            r = build_blocked_reply(q, qt, mode)
        else:
            r = None  # 放行 = 拿到真实地址
        results.append((name, parse_answer_ip(r)))
    usable = [n for n, ip in results if ip is not None]
    return blocked, results, usable


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pack")
    ap.add_argument("--mode", choices=["a-only", "full"], default="full")
    args = ap.parse_args()

    pk = Pack(args.pack)
    print(f"规则包: {pk.count} 条   模式: {args.mode}\n")

    # 一批真实广告/追踪域名（这些都应该被拦）
    ads = [
        "googleads.g.doubleclick.net",
        "pagead2.googlesyndication.com",
        "ads.facebook.com",
        "analytics.twitter.com",
        "api.umeng.com",
        "log.umeng.com",
        "w.cnzz.com",
        "app-measurement.com",
        "graph.facebook.com",
        "app.adjust.com",
        "api2.branch.io",
        "in.appcenter.ms",
        "ads.tiktok.com",
        "analytics.tiktok.com",
        "sdk.iad-01.braze.com",
        "api.mixpanel.com",
        "bat.bing.com",
        "ct.pinterest.com",
        "static.criteo.net",
        "ads.yahoo.com",
    ]

    total = ok = 0
    print(f"{'域名':42s} {'拦截':6s} {'客户端仍能拿到地址?':22s}")
    print("-" * 78)
    failed = []
    for d in ads:
        blocked, results, usable = test_domain(pk, d, args.mode)
        total += 1
        if blocked and not usable:
            ok += 1
            verdict = "否（拦截成功）"
        else:
            verdict = f"是 ← {','.join(usable) or '未拦截'}"
            failed.append(d)
        print(f"{d:42s} {'yes' if blocked else 'no':6s} {verdict}")

    print("-" * 78)
    print(f"有效拦截: {ok}/{total}  ({ok*100//total}%)")
    if failed:
        print(f"\n漏拦 {len(failed)} 个：")
        for d in failed:
            print(f"  - {d}")

    if args.mode == "a-only":
        print("\n这就是旧方案的问题：浏览器并行查 AAAA 和 HTTPS，"
              "只拦 A 记录时它从另外两条拿到了真实地址，压根不等 A 的结果。")


if __name__ == "__main__":
    main()

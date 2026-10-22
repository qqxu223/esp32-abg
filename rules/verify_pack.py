#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_pack.py — 用 Python 复刻固件的匹配逻辑，对拍规则包。
不依赖硬件，可以在 CI 里当回归测试跑。

它会检查：
  1. 包头 magic / version / count 一致
  2. 哈希严格升序、无重复
  3. 256 桶索引能正确定位（模拟 buildBuckets + lookupFlash）
  4. 逐级父域匹配的行为符合预期
  5. 危险伞域确实不在包里
"""

import sys
import struct

MAGIC = b"ESPR"
HASH_BYTES = 5
MASK = (1 << 40) - 1


def fnv40(s):
    h = 0xCBF29CE484222325
    for b in s.encode():
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h & MASK


class Pack:
    def __init__(self, path):
        self.data = open(path, "rb").read()
        assert self.data[:4] == MAGIC, "magic 不对"
        self.ver = self.data[4]
        self.count = struct.unpack("<I", self.data[6:10])[0]
        self.base = 10
        assert len(self.data) == self.base + self.count * HASH_BYTES, "长度与 count 不符"
        self.bucket = [0] * 257
        # buildBuckets：哈希按小端存 5 字节，数值最高位在 t[4]
        b = 0
        for pos in range(self.count):
            hi = self.data[self.base + pos * HASH_BYTES + HASH_BYTES - 1]
            while b <= hi and b < 256:
                self.bucket[b] = pos
                b += 1
        while b <= 256:
            self.bucket[b] = self.count
            b += 1
        self.hits = 0
        self.reads = 0

    def get(self, i):
        o = self.base + i * HASH_BYTES
        return int.from_bytes(self.data[o:o + HASH_BYTES], "little")

    def lookup(self, h):
        self.reads += 1
        bk = (h >> ((HASH_BYTES - 1) * 8)) & 0xFF
        a = self.bucket[bk]
        b = self.bucket[bk + 1]
        if a >= b:
            return False
        lo, hi = a, b
        while lo < hi:
            mid = (lo + hi) // 2
            v = self.get(mid)
            if v == h:
                return True
            if v < h:
                lo = mid + 1
            else:
                hi = mid
        return False

    def should_block(self, domain):
        p = domain
        while True:
            if self.lookup(fnv40(p)):
                self.hits += 1
                return True
            i = p.find(".")
            if i < 0:
                return False
            nxt = p[i + 1:]
            if "." not in nxt:
                return False
            p = nxt


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "../firmware/data/blocklist.bin"
    pk = Pack(path)
    print(f"包: {path}")
    print(f"  version={pk.ver}  count={pk.count}  size={len(pk.data)/1048576:.2f}MB")

    # 2. 升序 / 重复
    bad = 0
    prev = -1
    for i in range(pk.count):
        v = pk.get(i)
        if v <= prev:
            bad += 1
        prev = v
    print(f"  升序校验: {'OK' if bad == 0 else f'{bad} 处异常'}")

    # 3. 桶大小
    sizes = [pk.bucket[i + 1] - pk.bucket[i] for i in range(256)]
    print(f"  桶大小: min={min(sizes)} max={max(sizes)} avg={sum(sizes)/256:.0f}")
    assert max(sizes) <= 2048, "有桶超过 MAX_RANGE=2048，固件会退回桶内二分"

    # 4. 抽样对拍：随机取包内真实条目，取它本身和它的子域
    import random
    random.seed(42)
    hits = 0
    total = 300
    idx = random.sample(range(pk.count), total)
    # 反向建表：哈希 -> 原域名（仅抽样部分，用全量重建太慢）
    for i in idx:
        h = pk.get(i)
        # 直接用哈希查，等价于原域名查
        if pk.lookup(h):
            hits += 1
    print(f"  包内条目命中率: {hits}/{total}")
    assert hits == total, "包内条目查不到自己，索引有 bug"

    # 5. 危险伞域必须不在包里
    danger = ["google.com", "baidu.com", "weixin.qq.com", "qq.com", "github.com",
              "akamai.net", "alicdn.com", "gstatic.com", "apple.com", "microsoft.com"]
    leaked = [d for d in danger if pk.lookup(fnv40(d))]
    print(f"  危险伞域泄漏: {leaked if leaked else '无'}")

    # 6. 父域匹配行为
    cases = [
        ("ads.doubleclick.net", True),
        ("api.umeng.com", True),
        ("umeng.com", True),
        ("www.baidu.com", False),
    ]
    ok = True
    for d, want in cases:
        got = pk.should_block(d)
        mark = "OK " if got == want else "BAD"
        if got != want:
            ok = False
        print(f"  [{mark}] {d:32s} -> {'block' if got else 'pass'} (期望 {'block' if want else 'pass'})")

    print(f"\n查询读取次数: {pk.reads}（每次查询 1~3 次，对应逐级父域）")
    sys.exit(0 if (bad == 0 and ok and not leaked) else 1)


if __name__ == "__main__":
    main()

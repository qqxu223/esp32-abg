#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
flash.py — 把编译好的固件烧进 ESP32-S3（Windows/macOS/Linux 通用）

用法：
  python scripts/flash.py                     # 列出串口
  python scripts/flash.py COM5                # 烧录（自动 download 目录找固件）
  python scripts/flash.py COM5 --erase        # 先整片擦除
  python scripts/flash.py COM5 --file xxx.bin # 指定固件
  python scripts/flash.py COM5 --monitor      # 烧完直接看串口日志

固件来源二选一：
  1. out/firmware-merged.bin（CI 产出的整包，一次烧完，推荐）
  2. out/ 下的 bootloader.bin + partitions.bin + firmware.bin（分开烧）
"""

import argparse
import glob
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEARCH = [os.path.join(ROOT, "out"), os.path.join(ROOT, "downloads"), os.path.join(ROOT, "dist")]

# ESP32-S3 flash 布局
LAYOUT = [
    ("bootloader.bin", 0x0),
    ("partitions.bin", 0x8000),
    ("firmware.bin", 0x10000),
]


def find_ports():
    try:
        import serial.tools.list_ports as lp
    except ImportError:
        return []
    return list(lp.comports())


def locate(name):
    for d in SEARCH:
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
        hits = glob.glob(os.path.join(d, "**", name), recursive=True)
        if hits:
            return hits[0]
    return None


def run(cmd):
    print("$ " + " ".join(str(c) for c in cmd))
    r = subprocess.run(cmd)
    if r.returncode != 0:
        sys.exit(r.returncode)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", nargs="?", help="串口，如 COM5 / /dev/ttyUSB0")
    ap.add_argument("--erase", action="store_true", help="烧录前整片擦除")
    ap.add_argument("--file", help="指定固件文件")
    ap.add_argument("--baud", type=int, default=921600)
    ap.add_argument("--monitor", action="store_true", help="烧完打开串口监视")
    args = ap.parse_args()

    if not args.port:
        ports = find_ports()
        if not ports:
            print("没找到任何串口。检查 USB 线是否插好、驱动是否装上。")
            print("（ESP32-S3 用 USB-Serial/JTAG 时 PID 通常是 303A:1001）")
            sys.exit(2)
        print("可用串口：")
        for p in ports:
            print(f"  {p.device:16s} {p.description}  [{p.hwid}]")
        print(f"\n用法：python {sys.argv[0]} COM5")
        sys.exit(0)

    base = [sys.executable, "-m", "esptool", "--chip", "esp32s3", "-p", args.port, "-b", str(args.baud)]

    if args.erase:
        print("== 整片擦除（16MB）==")
        run(base + ["erase_flash"])

    if args.file:
        target = args.file
        if not os.path.exists(target):
            print(f"文件不存在：{target}")
            sys.exit(1)
        print(f"== 烧录整包 {target} ==")
        # 不带 --flash_mode/--flash_freq：保留镜像里 bootloader 头的时序设置
        # （qio/80m 在部分 S3 板上会让 bootloader 崩，CI 合包时已用 dio/40m）
        run(base + [
            "--before", "default_reset", "--after", "hard_reset",
            "write_flash", "--flash_size", "16MB",
            "0x0", target,
        ])
    else:
        merged = locate("firmware-merged.bin")
        if merged:
            print(f"== 烧录整包 {merged} ==")
            run(base + [
                "--before", "default_reset", "--after", "hard_reset",
                "write_flash", "--flash_size", "16MB",
                "0x0", merged,
            ])
            # 预装规则包的文件系统镜像（可选，不存在就跳过）
            lfs = locate("littlefs.img")
            if lfs:
                print(f"== 写入规则包镜像 {lfs} -> 0x810000 ==")
                run(base + [
                    "--before", "default_reset", "--after", "hard_reset",
                    "write_flash", "0x810000", lfs,
                ])
        else:
            parts = [(n, a, locate(n)) for n, a in LAYOUT]
            missing = [n for n, _, p in parts if not p]
            if missing:
                print("找不到固件：" + ", ".join(missing))
                print("把 CI 产物（firmware-merged.bin 或三个 bin）放到 out/ 目录再试。")
                sys.exit(1)
            print("== 分片烧录 ==")
            cmd = base + ["--before", "default_reset", "--after", "hard_reset",
                          "write_flash", "--flash_size", "16MB"]
            for name, addr, path in parts:
                cmd += [hex(addr), path]
            run(cmd)

    print("\n烧录完成。")
    print("  首次开机：没有 WiFi 配置 → 出现热点 AdBlock-XXXX，用手机连上去配网")
    print("  配网后：http://adblock.local 或设备 IP 打开诊断页")

    if args.monitor:
        print("\n== 串口日志（Ctrl+C 退出）==")
        subprocess.run([sys.executable, "-m", "serial.tools.miniterm", args.port, "115200"])


if __name__ == "__main__":
    main()

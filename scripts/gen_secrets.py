#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_secrets.py — 从环境变量生成 firmware/src/secrets.h

CI 里读 GitHub Secrets（前缀 S_），本地跑也可以直接给同名环境变量。
缺失的值会用安全的占位符填充，不会让编译失败。
"""

import os

TARGET = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "firmware", "src", "secrets.h")

DEFAULTS = [
    ("S_WEB_USER", "WEB_USER", "admin"),
    ("S_WEB_PASS", "WEB_PASS", "adblock-change-me"),
    ("S_OTA_PASS", "OTA_PASS", "adblock-ota-change-me"),
    ("S_WIFI_SSID", "WIFI_SSID", "YOUR_WIFI_SSID"),
    ("S_WIFI_PASS", "WIFI_PASS", "YOUR_WIFI_PASS"),
]

HEADER = """// secrets.h — 自动生成，请勿提交（.gitignore 已排除）
// 本地生成：python scripts/gen_secrets.py
#pragma once

"""


def cstr(v: str) -> str:
    # 转义反斜杠和双引号，避免生成非法 C 字面量
    return v.replace("\\", "\\\\").replace('"', '\\"')


def main():
    lines = [HEADER]
    for env_key, macro, fallback in DEFAULTS:
        val = os.environ.get(env_key) or fallback
        lines.append(f'#define {macro} "{cstr(val)}"\n')

    body = "".join(lines)
    with open(TARGET, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)

    # 只打印是否设置，不打印真实口令（CI 日志是公开的）
    for env_key, _, fallback in DEFAULTS:
        set_ = "已设置" if os.environ.get(env_key) else f"未设置，用默认值"
        print(f"  {env_key:14s} {set_}")
    print(f"已写入 {TARGET}")


if __name__ == "__main__":
    main()

# esp-fleet — ESP32-S3 DNS 广告拦截器

自用的家用 DNS 拦截盒子。改路由器 DNS 指向它，全屋设备（手机、电视、平板）的广告和追踪请求在解析阶段就被黑洞掉，不需要在每个设备上装插件。

硬件：**ESP32-S3 N16R8**（16MB flash + 8MB PSRAM），USB 直连电脑。

---

## 和常见开源方案的区别

网上的 ESP32 广告拦截项目（包括本项目的两个参考源）刷完之后"感觉没什么用"，核心原因只有一句话：

> **它们只拦 A 记录。**

浏览器解析一个域名时会**并行**发 A、AAAA、HTTPS(SVCB) 三条查询。旧实现只对 A 查询返回 `0.0.0.0`，但 AAAA 查询被原样转发给上游，HTTPS 查询也拿到真实的 SVCB 记录 —— 只要其中任何一条拿到真实地址，浏览器就直接连过去了，压根不等 A 的结果。

本项目的行为：

| 查询类型 | 被拦截时返回 |
|---|---|
| `A` (type 1) | `0.0.0.0`，TTL 60 |
| `AAAA` (type 28) | `::`（全零地址），TTL 60 |
| `HTTPS` / `SVCB` / `TXT` / 其余 | `NXDOMAIN`（断掉客户端退路） |

其他几点：

- **40 位哈希 + 256 桶索引**：34.7 万条规则压到 1.66MB，每次查询 1 次 seek + 1 次 read（不建桶的话要 ~19 次）
- **带校验的规则包**：`ESPR` + 版本 + 条目数，坏包开机直接拒载，不会静默退化成"不拦截"
- **上游故障自动放行**：上游 DNS 挂了就放行而不是阻断，30 秒探测一次自动恢复。断网比有广告更糟
- **国内追踪源补齐**：hagezi 对国内覆盖很弱（`umeng.com` 只有 1 条），手工补了友盟/CNZZ/神策/GrowingIO/TalkingData/秒针/广点通/穿山甲等主域通配
- **危险伞域剔除**：`akamai.net`、`alicdn.com`、`gstatic.com` 这类硬拦会直接"断网"，编译期就剔掉

---

## 目录结构

```
esp-fleet/
├── .github/workflows/build.yml   云端编译（不用本地装工具链）
├── firmware/
│   ├── platformio.ini            ESP32-S3 / 16MB / 双 OTA 分区
│   ├── partitions_s3_16mb.csv
│   ├── data/blocklist.bin        规则包（34.7 万条，1.66MB，已入库）
│   └── src/
│       ├── main.cpp              DNS 服务、Web 后台、配网、OTA
│       ├── adblock.h             拦截引擎（分桶索引 + 全 QTYPE 应答）
│       └── secrets.example.h     口令模板（真实 secrets.h 不进仓库）
├── rules/
│   ├── build_rules.py            规则编译器
│   └── verify_pack.py            规则包对拍校验（CI 里跑）
└── scripts/flash.py              烧录脚本
```

---

## 从零到能拦截

### 1. 云端编译（推荐，不需要本地工具链）

推代码到 GitHub 后，Actions 会自动跑 `build` 工作流。也可以在网页上手动触发：

**Actions → build → Run workflow**，填个版本号即可。

跑完在 workflow 页面底部下载 artifact `esp32s3-adblock-<版本>`，里面有：

```
firmware-merged.bin    ← 一次烧完的整包（推荐）
firmware.bin           ← 只用 OTA 升级时用这个
bootloader.bin
partitions.bin
blocklist.bin
```

> 想在本地编译也行：`cd firmware && pio run -e s3`。前提是能正常下载 xtensa 工具链。

### 2. 烧录

```bash
python scripts/flash.py                 # 先看串口
python scripts/flash.py COM5            # 烧
python scripts/flash.py COM5 --erase    # 反复起不来时整片擦除重烧
```

### 3. 配网

首次开机没有 WiFi 记录，设备会开一个热点：

- 热点名：`AdBlock-XXXX`（XXXX 是 MAC 后两位）
- 手机连上去，随便打开一个网页会被劫持到配网页（Captive Portal）
- 填 WiFi 名和密码，保存后设备自动重启入网

想重新配网：**按住 BOOT 键（GPIO0）开机** 3 秒，会清掉 WiFi 配置重新进 AP 模式。

### 4. 让路由器把 DNS 交给它

设备入网后，把路由器的 **DHCP 下发的 DNS** 改成设备的 IP（不是改 WAN DNS —— 那只会影响路由器自己）。

设备 IP 在配网页和 `http://adblock.local` 都能看到。建议先在路由器上给它的 MAC 绑定一个固定 IP，否则重启后 IP 变了又要改一遍。

### 5. 验证有没有生效

打开 `http://adblock.local`（或设备 IP），页面会跑一遍自检：

```
[OK] 规则包已加载        rules=347385 size=1696KB magic=ok ver=2 bucket=ok
[OK] 规则数量充足        347385 条
[OK] 上游 DNS 可达       正常
[OK] 有客户端在查询      3 台
[OK] 已产生拦截          1240 次
[NG] 拦截占比合理        0.4%（正常 8%~25%，0% 说明路由器没接管）
```

最后一项是关键：**拦截占比低于 3% 基本可以断定路由器没真正接管 DNS**。常见原因：只改了 WAN DNS、路由器有硬编码的备用 DNS、或者设备走的是 IPv6 的 DNS。

---

## Web 接口

所有写操作要求两个条件同时满足：`X-Requested-With: adblock` 头（防 CSRF）+ Basic Auth。

| 路径 | 方法 | 说明 |
|---|---|---|
| `/` | GET | 诊断页 |
| `/stats.json` | GET | 统计（拦截数、TOP 域名、客户端） |
| `/diag.json` | GET | 自检清单 |
| `/info.json` | GET | 设备信息（SN / MAC / 固件版本） |
| `/pause` `/resume` | GET | 暂停 / 恢复拦截（认证后） |
| `/allow?d=example.com` | GET | 加白名单（认证后） |
| `/upload` | POST | 上传新规则包（认证后，原子替换） |
| `/update` | POST | 上传新固件（认证后） |

规则包替换是"先写 `blocklist.new` → 校验 magic/size → 删旧 → rename"，中途断电最多丢新包，旧包还在。

---

## 更新规则

规则会过期。建议每次发版前重新编译一次：

```bash
cd rules
python build_rules.py --profile ultimate --offline .cache \
       --out ../firmware/data/blocklist.bin
python verify_pack.py ../firmware/data/blocklist.bin
```

档位说明：

| profile | 条目数 | 适用 |
|---|---|---|
| `light` | ~6.7 万 | 怕误杀 |
| `pro` | ~20 万 | 平衡 |
| `ultimate` | ~34 万 | **当前默认** |
| `max` | ~60 万 | 最激进，误杀率明显上升 |

不重新烧固件也能更新规则：浏览器打开设备页面，用 `/upload` 传新的 `blocklist.bin`（需要口令）。

---

## 出问题了

**刷完还是满屏广告**
1. 看诊断页"拦截占比"。0% 或接近 0% → 路由器没接管，回去看第 4 步
2. 占比正常（10%+）但还是有广告 → 大部分是**同域名的第一方广告**（比如微博信息流里的推广），DNS 层拦不住，这是原理限制
3. YouTube 广告拦不掉 —— 它的广告和视频走同一个域名

**某些 App 或网站打不开了**
1. 诊断页看 TOP 域名，找到被误杀的
2. `http://<设备IP>/allow?d=example.com` 加白（需要口令）—— 放行主域会连带放行所有子域
3. 如果是规则包本身的问题，在 `rules/build_rules.py` 的 `BANNED_SUFFIX` 里加进去，重新编译规则包

**设备反复重启 / 起不来**
```bash
python scripts/flash.py COM5 --erase
```
整片擦除后重烧。

**看不到串口**
ESP32-S3 用原生 USB 时，某些线材只供电不传数据。换一根数据线。设备管理器里应该能看到 `USB-SERIAL CH340` 或者 VID:PID = `303A:1001`。

---

## 关于用法

这套东西是自用工具。有两点值得说明：

- 广告拦截本身在国内不违法，但**如果做成商品卖**，会碰到《反不正当竞争法》里"妨碍、破坏其他经营者合法提供的网络产品正常运行"的条款，风险来自这里，不是来自技术本身
- 参考的两个开源项目：`M-Abozaid/esp32-c3-adblock` 是 MIT；`s60sc/ESP32_AdBlocker` **没有 LICENSE 文件**，默认保留所有权利，代码不能直接用。本项目的 DNS 引擎和规则编译都是重写的，只借鉴了思路

---

## 许可

MIT

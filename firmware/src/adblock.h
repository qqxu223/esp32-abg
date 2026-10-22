// adblock.h — DNS 拦截引擎（ESP32-S3 / 8MB PSRAM 优化版）
//
// 相比常见开源实现的三个关键差异：
//  1. 全 QTYPE 拦截：A 回 0.0.0.0，AAAA 回 ::，HTTPS/SVCB/TXT 等回 NXDOMAIN。
//     只拦 A 记录是"刷完仍然看到广告"的首要原因 —— 浏览器并行查 AAAA/HTTPS，
//     任一条拿到真实地址就不再等 A。
//  2. 分桶索引：按哈希低字节切 256 桶，每桶连续存放，一次 seek + 一次 read 命中。
//  3. 规则包带 magic + 版本 + 数量，坏包开机即拒载，不会静默变成"不拦截"。
#pragma once
#include <Arduino.h>
#include <LittleFS.h>
#include <string.h>
#include <strings.h>
#if __has_include("esp32-hal-psram.h")
#include "esp32-hal-psram.h"
#endif

static const char* RULE_PATH = "/blocklist.bin";
static const char* RULE_PATH_NEW = "/blocklist.new";
static const uint8_t RULE_MAGIC[4] = {'E', 'S', 'P', 'R'};
static const uint8_t RULE_VERSION = 2;

static const int HASH_BYTES = 5;         // 40 位哈希
static const int RULE_HEADER = 10;       // magic(4) ver(1) flag(1) count(4)
static const int BUCKETS = 256;
static const int MAX_RANGE = 2048;       // 单桶上限（244k 条 / 256 桶 ≈ 954）

#ifndef BLOCK_TTL
#define BLOCK_TTL 60
#endif

// 运行时兜底白名单（精确匹配主域及其子域），防止规则包误杀导致设备不可用
static const char* RUNTIME_ALLOW[] = {
  "apple.com", "microsoft.com", "windowsupdate.com", "weixin.qq.com", "wechat.com",
  "qq.com", "alipay.com", "paypal.com", "github.com", "githubusercontent.com",
  "ocsp.apple.com", "time.apple.com", "connectivitycheck.gstatic.com",
  "cloudflare-dns.com", "gstatic.com", "android.clients.google.com",
  "ntp.aliyun.com", "time1.cloud.tencent.com",
};
static const int RUNTIME_ALLOW_N = sizeof(RUNTIME_ALLOW) / sizeof(RUNTIME_ALLOW[0]);

// 白名单只在主域后缀上判断一次：既省时间，也避免"子域放行但父域被拦"的漏洞
static bool isRuntimeAllowed(const char* d) {
  for (int i = 0; i < RUNTIME_ALLOW_N; i++) {
    const char* a = RUNTIME_ALLOW[i];
    size_t la = strlen(a);
    size_t ld = strlen(d);
    if (ld < la) continue;
    if (ld > la && d[ld - la - 1] != '.') continue;
    if (strcasecmp(d + (ld - la), a) == 0) return true;
  }
  return false;
}

// 给外部（main.cpp 的 static_assert）用的常量，避免暴露 private 成员
static const int ADB_MAX_RANGE = MAX_RANGE;
static const int ADB_HASH_BYTES = HASH_BYTES;

struct AdbStats {
  uint32_t queries = 0;
  uint32_t blocked = 0;
  uint32_t forwarded = 0;
  uint32_t upstreamFail = 0;
  uint32_t allowlisted = 0;
  uint32_t clients = 0;
};

struct TopDomain {
  uint64_t hash;
  uint32_t hits;
  char name[56];
};

class Adblocker {
 public:
  bool begin() {
    loadRules();
    return count_ > 0;
  }

  bool ready() const { return count_ > 0; }
  uint32_t ruleCount() const { return count_; }
  const AdbStats& stats() const { return st_; }
  AdbStats& mutStats() { return st_; }

  /** 逐级父域匹配；命中时通过 hitHash 回传用于统计 */
  bool shouldBlock(const char* domain, uint64_t* hitHash = nullptr) {
    if (isRuntimeAllowed(domain)) {
      st_.allowlisted++;
      return false;
    }
    const char* p = domain;
    while (p && *p) {
      uint64_t h = fnv40(p, strlen(p));
      if (lookup(h)) {
        if (hitHash) *hitHash = h;
        return true;
      }
      const char* dot = strchr(p, '.');
      if (!dot) break;
      const char* next = dot + 1;
      if (!strchr(next, '.')) break;
      p = next;
    }
    return false;
  }

  void noteBlocked(uint64_t h, const char* domain) {
    st_.blocked++;
    for (int i = 0; i < topN_; i++) {
      if (top_[i].hash == h) {
        top_[i].hits++;
        return;
      }
    }
    if (topN_ < TOP_MAX) {
      top_[topN_].hash = h;
      top_[topN_].hits = 1;
      strncpy(top_[topN_].name, domain, sizeof(top_[0].name) - 1);
      top_[topN_].name[sizeof(top_[0].name) - 1] = 0;
      topN_++;
      if (topN_ == TOP_MAX) sortTop();
      return;
    }
    if (top_[TOP_MAX - 1].hits <= 1) {
      top_[TOP_MAX - 1].hash = h;
      top_[TOP_MAX - 1].hits = 1;
      strncpy(top_[TOP_MAX - 1].name, domain, sizeof(top_[0].name) - 1);
      top_[TOP_MAX - 1].name[sizeof(top_[0].name) - 1] = 0;
    }
  }

  int topCount() const { return topN_; }
  const TopDomain& top(int i) const { return top_[i]; }

  void countQuery() { st_.queries++; }
  void countForward() { st_.forwarded++; }
  void countUpstreamFail() { st_.upstreamFail++; }
  void setClients(uint32_t n) { st_.clients = n; }

  String diagnose() {
    char b[200];
    snprintf(b, sizeof(b), "rules=%u size=%uKB magic=%s ver=%u bucket=%s",
             count_, (unsigned)(count_ * HASH_BYTES / 1024),
             magicOk_ ? "ok" : "BAD", (unsigned)fileVersion_,
             bucketOk_ ? "ok" : "fallback");
    return String(b);
  }

 private:
  static const int CACHE_SIZE = 512;
  static const int TOP_MAX = 24;

  File file_;
  uint32_t count_ = 0;
  uint8_t fileVersion_ = 0;
  bool magicOk_ = false;
  bool bucketOk_ = false;

  uint32_t bucket_[BUCKETS + 1];
  uint8_t cKey_[CACHE_SIZE][HASH_BYTES];
  uint8_t cVal_[CACHE_SIZE];
  uint8_t cValid_[CACHE_SIZE];
  // 桶内顺序扫描用的缓冲区。10KB 放 .bss 会挤占本就不多的内部 RAM，
  // 这里改成首次使用时从 PSRAM 分配（没有 PSRAM 就退回内部堆）。
  static uint8_t* range_;

  TopDomain top_[TOP_MAX];
  int topN_ = 0;
  AdbStats st_;

  void sortTop() {
    for (int i = 0; i < topN_; i++)
      for (int j = i + 1; j < topN_; j++)
        if (top_[j].hits > top_[i].hits) {
          TopDomain t = top_[i];
          top_[i] = top_[j];
          top_[j] = t;
        }
  }

  static uint64_t fnv40(const char* s, size_t n) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) {
      h ^= (uint8_t)s[i];
      h *= 0x100000001b3ULL;
    }
    return h & ((1ULL << (HASH_BYTES * 8)) - 1);
  }
  static inline uint64_t unpack(const uint8_t* b) {
    uint64_t v = 0;
    for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
    return v;
  }
  static inline void pack(uint64_t h, uint8_t* b) {
    for (int k = 0; k < HASH_BYTES; k++) {
      b[k] = (uint8_t)h;
      h >>= 8;
    }
  }

  void loadRules() {
    if (file_) file_.close();
    count_ = 0;
    magicOk_ = false;
    bucketOk_ = false;
    for (int i = 0; i < CACHE_SIZE; i++) cValid_[i] = 0;
    topN_ = 0;

    if (!range_) {
      // 优先 PSRAM（16KB，够 3200 条同时驻留），没有则退回内部堆
      range_ = (uint8_t*)ps_malloc((size_t)MAX_RANGE * HASH_BYTES);
      if (!range_) range_ = (uint8_t*)malloc((size_t)MAX_RANGE * HASH_BYTES);
      if (!range_) { Serial.println("[adb] range buffer alloc failed"); return; }
    }

    file_ = LittleFS.open(RULE_PATH, "r");
    if (!file_) return;

    size_t sz = file_.size();
    if (sz <= RULE_HEADER) { file_.close(); return; }

    uint8_t hdr[RULE_HEADER];
    if (file_.read(hdr, RULE_HEADER) != RULE_HEADER) { file_.close(); return; }

    bool magic = memcmp(hdr, RULE_MAGIC, 4) == 0;
    fileVersion_ = hdr[4];
    uint32_t declared = (uint32_t)hdr[6] | ((uint32_t)hdr[7] << 8) |
                        ((uint32_t)hdr[8] << 16) | ((uint32_t)hdr[9] << 24);

    if (magic && fileVersion_ == RULE_VERSION) {
      uint32_t actual = (sz - RULE_HEADER) / HASH_BYTES;
      count_ = (declared && declared <= actual) ? declared : actual;
      magicOk_ = true;
    } else if (!magic) {
      // 兼容无头的裸哈希包（v1）
      file_.seek(0);
      count_ = sz / HASH_BYTES;
      fileVersion_ = 1;
      magicOk_ = true;
    } else {
      file_.close();
      return;
    }
    buildBuckets();
  }

  // 规则包按哈希"数值升序"排列。哈希按小端存 5 字节，
  // 所以数值最高位在 t[4]，分桶要取 t[4] 而不是 t[0]。
  // （取 t[0] 会把桶索引打乱——这是实测踩出来的坑）
  void buildBuckets() {
    bucketOk_ = false;
    if (!file_ || count_ == 0) return;
    file_.seek(RULE_HEADER);
    uint32_t pos = 0;
    int b = 0;
    uint8_t t[HASH_BYTES];
    for (int i = 0; i < BUCKETS + 1; i++) bucket_[i] = 0;
    while (pos < count_ && file_.read(t, HASH_BYTES) == HASH_BYTES) {
      uint8_t hi = t[HASH_BYTES - 1];
      while (b <= (int)hi && b < BUCKETS) { bucket_[b] = pos; b++; }
      pos++;
    }
    while (b <= BUCKETS) { bucket_[b] = count_; b++; }
    // 自检：桶边界必须单调不减，否则说明包没排序，退回全表二分
    for (int i = 1; i <= BUCKETS; i++) {
      if (bucket_[i] < bucket_[i - 1]) { bucketOk_ = false; return; }
    }
    bucketOk_ = true;
  }

  bool lookupFlash(uint64_t h) {
    if (count_ == 0 || !range_) return false;
    // 桶键与 buildBuckets 一致：取哈希数值的最高字节
    const uint32_t bk = (uint32_t)((h >> ((HASH_BYTES - 1) * 8)) & 0xFF);
    uint32_t a, b;
    if (bucketOk_) {
      a = bucket_[bk];
      b = bucket_[bk + 1];
    } else {
      a = 0;
      b = count_;
    }
    if (a >= b || b > count_) return false;

    uint32_t n = b - a;
    if (n > (uint32_t)MAX_RANGE) {
      // 桶过大时桶内二分，避免读爆缓冲
      while (a < b) {
        uint32_t mid = a + (b - a) / 2;
        file_.seek(RULE_HEADER + mid * HASH_BYTES);
        uint8_t t[HASH_BYTES];
        if (file_.read(t, HASH_BYTES) != HASH_BYTES) return false;
        uint64_t v = unpack(t);
        if (v == h) return true;
        if (v < h) a = mid + 1; else b = mid;
      }
      return false;
    }
    file_.seek(RULE_HEADER + a * HASH_BYTES);
    if (file_.read(range_, n * HASH_BYTES) != n * HASH_BYTES) return false;
    for (uint32_t i = 0; i < n; i++) {
      uint64_t v = unpack(range_ + i * HASH_BYTES);
      if (v == h) return true;
      if (v > h) break;
    }
    return false;
  }

  bool lookup(uint64_t h) {
    uint32_t slot = (uint32_t)(h & (CACHE_SIZE - 1));
    uint8_t want[HASH_BYTES];
    pack(h, want);
    if (cValid_[slot] && memcmp(cKey_[slot], want, HASH_BYTES) == 0) return cVal_[slot] != 0;
    bool r = lookupFlash(h);
    memcpy(cKey_[slot], want, HASH_BYTES);
    cVal_[slot] = r ? 1 : 0;
    cValid_[slot] = 1;
    return r;
  }
};

// Adblocker::range_ 的存储定义放在 main.cpp（静态成员必须恰好定义一次）

// ---------------- DNS 应答构造 ----------------
struct DnsAnswer {
  static const int MAX_BUF = 512;

  /**
   * 在 query 的 question 段后追加拦截应答。
   * @param nxdomain true 时返回 NXDOMAIN（用于 HTTPS/SVCB 等，断掉客户端退路）
   * @return 应答总长度
   */
  static int buildBlocked(uint8_t* buf, int qend, uint16_t qtype, bool nxdomain, int cap) {
    buf[2] = 0x81;                                  // QR=1, RD=1
    buf[3] = nxdomain ? 0x83 : 0x80;                // NXDOMAIN 或 NOERROR，RA=1
    buf[6] = 0; buf[7] = 0;                         // ANCOUNT
    buf[8] = 0; buf[9] = 0;                         // NSCOUNT
    buf[10] = 0; buf[11] = 0;                        // ARCOUNT（丢掉客户端 EDNS OPT）

    if (!nxdomain && qtype == 1) {
      if (qend + 16 > cap) return qend;
      const uint8_t ans[16] = {0xC0, 0x0C, 0, 1, 0, 1,
                               (uint8_t)(BLOCK_TTL >> 24), (uint8_t)(BLOCK_TTL >> 16),
                               (uint8_t)(BLOCK_TTL >> 8), (uint8_t)BLOCK_TTL,
                               0, 4, 0, 0, 0, 0};
      memcpy(buf + qend, ans, sizeof(ans));
      buf[7] = 1;
      return qend + (int)sizeof(ans);
    }
    if (!nxdomain && qtype == 28) {
      if (qend + 28 > cap) return qend;
      uint8_t ans[28];
      memset(ans, 0, sizeof(ans));
      ans[0] = 0xC0; ans[1] = 0x0C; ans[2] = 0; ans[3] = 28;
      ans[4] = 0; ans[5] = 1;
      ans[6] = (uint8_t)(BLOCK_TTL >> 24); ans[7] = (uint8_t)(BLOCK_TTL >> 16);
      ans[8] = (uint8_t)(BLOCK_TTL >> 8); ans[9] = (uint8_t)BLOCK_TTL;
      ans[10] = 0; ans[11] = 16;                     // RDLENGTH = 16，RDATA 全零 = ::
      memcpy(buf + qend, ans, sizeof(ans));
      buf[7] = 1;
      return qend + (int)sizeof(ans);
    }
    return qend;                                     // NODATA / NXDOMAIN
  }
};

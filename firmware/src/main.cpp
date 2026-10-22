// main.cpp — ESP32-S3 DNS 广告拦截器
// 特性：全 QTYPE 拦截 / 分桶索引 / 上游故障自动放行 / 一键诊断 / Web OTA
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>
#include <ArduinoOTA.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <strings.h>
// 注意：lwIP 的 etharp.h 必须在 Arduino.h 之后引入，否则 ARDUINO 宏为 0
// 而 lwIP 会走"独立模式"声明 err_t etharp_find_addr(netif*, ...)
extern "C" {
#include <lwip/etharp.h>
#include <lwip/netif.h>
}
// core 3.x 才有 esp_netif（core 2.x 直接用 netif_default）
#if __has_include(<esp_netif.h>)
#include <esp_netif.h>
#define ADB_HAVE_ESP_NETIF 1
#endif
#include "adblock.h"
#include "secrets.h"

// 版本号：CI 会生成 version.h，本地没有就用默认值
#if __has_include("version.h")
#include "version.h"
#endif
#ifndef FW_VERSION
#define FW_VERSION "2.0.0-dev"
#endif

#ifndef UPSTREAM_IP
#define UPSTREAM_IP 223, 5, 5, 5
#endif

static const uint16_t DNS_PORT = 53;
// 上游 DNS：主用阿里，备用腾讯。不用 8.8.8.8 —— 国内连通性差，
// 而且它会对部分被墙域名返回假地址，反而让"屏蔽"看起来像生效了
static IPAddress upstreamIp(UPSTREAM_IP);
static IPAddress upstreamAlt(119, 29, 29, 29);
static const char* DEVID_PATH = "/devid.cfg";
static const int MAX_CLIENTS = 64;
static const int MAX_CUSTOM_ALLOW = 64;

WiFiUDP dnsServer;
WiFiUDP upstreamCli;
WebServer web(80);
Adblocker adb;
Preferences prefs;
DNSServer dnsPortal;

static uint8_t pktBuf[1536];
bool blockingOn = true;
bool upstreamHealthy = true;
uint32_t lastProbeMs = 0;

// Adblocker 的静态成员存储（必须恰好定义一次）
uint8_t* Adblocker::range_ = nullptr;

static char deviceSn[24] = "UNPROVISIONED";
static char deviceKey[48] = "";
static char serverUrl[96] = "";

struct Dev {
  uint32_t ip;
  uint8_t mac[6];
  uint32_t blocked;
  uint32_t allowed;
  uint32_t lastSeen;
};
static Dev clients[MAX_CLIENTS];
int numClients = 0;

String customAllow[MAX_CUSTOM_ALLOW];
int numCustomAllow = 0;

// ---------------- 前向声明（避免隐式声明导致的编译错误） ----------------
static void handleStats();
static void handleDiag();
static void handleInfo();
static void handleRulesUpload();
static void handleRulesDone();
static void handleFwUpload();
static void handleFwDone();
static void handlePortalRoot();
static void handleWifiSave();
static bool requireAuth();
static bool swapRules();
static bool connectWiFi();
static void startConfigPortal();
static void loadCustomAllow();
static bool saveCustomAllow();
static void loadDeviceId();
static bool saveDeviceId(const String&, const String&, const String&);
static String htmlEscape(const String&);
static Dev* getClient(uint32_t);
static void probeUpstream();

// ---------------- 编译期自检 ----------------
static_assert(sizeof(Dev) <= 64, "Dev 结构过大，检查 MAX_CLIENTS 内存占用");
static_assert(ADB_MAX_RANGE * ADB_HASH_BYTES <= 16 * 1024, "range_ 缓冲区过大");

// ---------------- 自定义放行 ----------------
static void loadCustomAllow() {
  numCustomAllow = 0;
  File f = LittleFS.open("/allow.txt", "r");
  if (!f) return;
  while (f.available() && numCustomAllow < MAX_CUSTOM_ALLOW) {
    String l = f.readStringUntil('\n');
    l.trim();
    l.toLowerCase();
    if (l.length() > 3 && l.indexOf('.') > 0) customAllow[numCustomAllow++] = l;
  }
  f.close();
}

static bool saveCustomAllow() {
  File f = LittleFS.open("/allow.txt", "w");
  if (!f) return false;
  for (int i = 0; i < numCustomAllow; i++) f.println(customAllow[i]);
  f.close();
  return true;
}

// 自定义放行：精确匹配 + 子域匹配（放行 example.com 等于放行 a.example.com）
static bool inCustomAllow(const char* d) {
  size_t ld = strlen(d);
  for (int i = 0; i < numCustomAllow; i++) {
    const char* a = customAllow[i].c_str();
    size_t la = customAllow[i].length();
    if (ld < la) continue;
    if (ld > la && d[ld - la - 1] != '.') continue;
    if (strcasecmp(d + (ld - la), a) == 0) return true;
  }
  return false;
}

// ---------------- 设备身份 ----------------
static void loadDeviceId() {
  File f = LittleFS.open(DEVID_PATH, "r");
  if (!f) return;
  String a = f.readStringUntil('\n'); a.trim();
  String b = f.readStringUntil('\n'); b.trim();
  String c = f.readStringUntil('\n'); c.trim();
  f.close();
  if (a.length() && a != "UNPROVISIONED") a.toCharArray(deviceSn, sizeof(deviceSn));
  b.toCharArray(deviceKey, sizeof(deviceKey));
  c.toCharArray(serverUrl, sizeof(serverUrl));
}

static bool saveDeviceId(const String& sn, const String& key, const String& srv) {
  File f = LittleFS.open(DEVID_PATH, "w");
  if (!f) return false;
  f.println(sn);
  f.println(key);
  f.println(srv);
  f.close();
  sn.toCharArray(deviceSn, sizeof(deviceSn));
  key.toCharArray(deviceKey, sizeof(deviceKey));
  srv.toCharArray(serverUrl, sizeof(serverUrl));
  return true;
}

// ---------------- DNS ----------------
static size_t parseQuery(const uint8_t* p, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0;
  int i = 12;
  size_t o = 0;
  while (i < len) {
    uint8_t l = p[i++];
    if (l == 0) break;
    if (l & 0xC0) return 0;              // 查询段不允许压缩指针
    if (l > 63) return 0;                // 单标签最长 63
    if (o + l + 1 >= 250 || i + l > len) return 0;
    if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) {
      uint8_t ch = p[i++];
      // 只接受字母数字、连字符、下划线和点；其余（空格/控制字符/中文）一律丢弃
      bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
      if (!ok) return 0;
      out[o++] = (char)((ch >= 'A' && ch <= 'Z') ? ch + 32 : ch);
    }
  }
  out[o] = 0;
  if (o < 3) return 0;                   // 至少 a.b
  if (i + 4 > len) return 0;
  *qtype = (uint16_t)((p[i] << 8) | p[i + 1]);
  *qend = i + 4;
  return o;
}

// 把整包转发给上游并等待应答。成功返回应答长度（已写回 pktBuf），失败返回 0。
static int forwardUpstream(int qlen, int qend) {
  while (upstreamCli.parsePacket() > 0) upstreamCli.flush();

  const uint8_t cid0 = pktBuf[0], cid1 = pktBuf[1];
  const uint16_t wid = (uint16_t)esp_random();
  // 备份 question 段：上游应答回来时逐字节比对，防串包 / 防投毒
  uint8_t q[260];
  int ql = qend - 12;
  if (ql < 0 || ql > (int)sizeof(q)) return 0;
  if (ql > 0) memcpy(q, pktBuf + 12, ql);

  pktBuf[0] = (uint8_t)(wid >> 8);
  pktBuf[1] = (uint8_t)(wid & 0xFF);
  upstreamCli.beginPacket(upstreamHealthy ? upstreamIp : upstreamAlt, DNS_PORT);
  upstreamCli.write(pktBuf, qlen);
  upstreamCli.endPacket();

  const uint32_t t0 = millis();
  while (millis() - t0 < 1200) {
    int sz = (int)upstreamCli.parsePacket();
    if (sz <= 0) {
      delay(1);
      continue;
    }
    int n = (int)upstreamCli.read(pktBuf, sizeof(pktBuf));
    upstreamCli.flush();
    if (n < 12 || sz > (int)sizeof(pktBuf)) continue;
    if (pktBuf[0] != (uint8_t)(wid >> 8) || pktBuf[1] != (uint8_t)(wid & 0xFF)) continue;
    if (n < 12 + ql || memcmp(pktBuf + 12, q, ql) != 0) continue;
    pktBuf[0] = cid0;
    pktBuf[1] = cid1;
    return n;
  }
  adb.countUpstreamFail();
  upstreamHealthy = false;
  return 0;
}

static void handleDns() {
  for (int budget = 0; budget < 24; budget++) {
    int sz = (int)dnsServer.parsePacket();
    if (sz <= 0) return;

    int qlen = (int)dnsServer.read(pktBuf, sizeof(pktBuf));
    adb.countQuery();
    if (qlen < 13) continue;

    // 先取副本：forwardUpstream() 会就地改写 pktBuf
    IPAddress cip = dnsServer.remoteIP();
    uint16_t cport = dnsServer.remotePort();
    char domain[256];
    memset(domain, 0, sizeof(domain));
    uint16_t qtype = 0;
    int qend = qlen;
    parseQuery(pktBuf, qlen, domain, &qtype, &qend);

    if (domain[0] == 0) continue;  // 解析失败：不转发、不阻断，丢弃

    Dev* c = getClient((uint32_t)cip);
    bool blockIt = blockingOn && adb.ready() && !inCustomAllow(domain);
    if (blockIt) {
      uint64_t hit = 0;
      blockIt = adb.shouldBlock(domain, &hit);
      if (blockIt) adb.noteBlocked(hit, domain);
    }

    int rlen = 0;
    if (blockIt) {
      bool nx = (qtype != 1 && qtype != 28);
      rlen = DnsAnswer::buildBlocked(pktBuf, qend, qtype, nx, (int)sizeof(pktBuf));
      if (c) c->blocked++;
    } else {
      rlen = forwardUpstream(qlen, qend);
      if (rlen > 0) {
        adb.countForward();
        if (c) c->allowed++;
      }
    }
    if (rlen > 0) {
      dnsServer.beginPacket(cip, cport);
      dnsServer.write(pktBuf, rlen);
      dnsServer.endPacket();
    }
  }
}

// ---------------- 上游探测 ----------------
static bool rawProbe(const IPAddress& ip) {  if (!upstreamCli.beginPacket(ip, DNS_PORT)) return false;
  uint8_t q[29] = {0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                   0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01};
  upstreamCli.write(q, sizeof(q));
  upstreamCli.endPacket();
  uint32_t t0 = millis();
  while (millis() - t0 < 800) {
    if (upstreamCli.parsePacket() > 0) {
      upstreamCli.flush();
      return true;
    }
    delay(5);
  }
  return false;
}

static void probeUpstream() {
  if (millis() - lastProbeMs < 30000) return;
  lastProbeMs = millis();
  bool ok = rawProbe(upstreamHealthy ? upstreamIp : upstreamAlt);
  if (!ok) ok = rawProbe(upstreamHealthy ? upstreamAlt : upstreamIp);
  if (ok != upstreamHealthy) Serial.printf("[dns] upstream %s\n", ok ? "recovered" : "down, fail-open");
  upstreamHealthy = ok;
}

// ---------------- 客户端表 ----------------
// 只是拿来显示在统计页，拿不到 MAC 就留空，不影响拦截
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6);
  if (ip == 0) return;
  ip4_addr_t ipa;
  ipa.addr = ip;

  struct netif* target = nullptr;
#if defined(ADB_HAVE_ESP_NETIF)
  // core 3.x：WiFi 的 netif 要通过 esp_netif 拿
  esp_netif_t* nif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (nif) target = (struct netif*)esp_netif_get_netif_impl(nif);
#else
  target = netif_default;
#endif
  if (!target) return;

  struct eth_addr* eth = nullptr;
  const ip4_addr_t* ipret = nullptr;
  if (etharp_find_addr(target, &ipa, &eth, &ipret) >= 0 && eth) {
    memcpy(mac, eth->addr, 6);
  }
}

static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++)
    if (clients[i].ip == ip) {
      clients[i].lastSeen = millis();
      return &clients[i];
    }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip;
    c->blocked = 0;
    c->allowed = 0;
    c->lastSeen = millis();
    getMac(ip, c->mac);
    adb.setClients((uint32_t)numClients);
    return c;
  }
  return nullptr;
}

// ---------------- 工具 ----------------
static String jesc(const String& s) {
  String o;
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '"' || c == '\\') o += '\\';
    o += c;
  }
  return o;
}

static String htmlEscape(const String& s) {
  String o;
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    switch (c) {
      case '&': o += "&amp;"; break;
      case '<': o += "&lt;"; break;
      case '>': o += "&gt;"; break;
      case 0x22: o += "&quot;"; break;
      case 0x27: o += "&#39;"; break;
      default: o += c;
    }
  }
  return o;
}

// ---------------- Web 接口 ----------------
static void handleStats() {
  const AdbStats& s = adb.stats();
  uint32_t total = s.blocked + s.forwarded;
  double rate = total ? (double)s.blocked * 100.0 / total : 0.0;
  String j = "{";
  j += "\"sn\":\"" + String(deviceSn) + "\",";
  j += "\"ip\":\"" + WiFi.localIP().toString() + "\",";
  j += "\"fw\":\"" FW_VERSION "\",";
  j += "\"rules\":" + String(adb.ruleCount()) + ",";
  j += "\"blocked\":" + String(s.blocked) + ",";
  j += "\"allowed\":" + String(s.forwarded) + ",";
  j += "\"rate\":" + String(rate, 1) + ",";
  j += "\"upFail\":" + String(s.upstreamFail) + ",";
  j += "\"upOk\":" + String(upstreamHealthy ? "true" : "false") + ",";
  j += "\"blocking\":" + String(blockingOn ? "true" : "false") + ",";
  j += "\"clients\":" + String(numClients) + ",";
  j += "\"rssi\":" + String(WiFi.RSSI()) + ",";
  j += "\"heap\":" + String(ESP.getFreeHeap()) + ",";
  j += "\"psram\":" + String(ESP.getFreePsram()) + ",";
  j += "\"uptime\":" + String(millis() / 1000) + ",";
  j += "\"diag\":\"" + jesc(adb.diagnose()) + "\",";
  j += "\"top\":[";
  for (int i = 0; i < adb.topCount(); i++) {
    if (i) j += ",";
    j += "{\"d\":\"" + jesc(String(adb.top(i).name)) + "\",\"n\":" + String(adb.top(i).hits) + "}";
  }
  j += "],\"allow\":[";
  for (int i = 0; i < numCustomAllow; i++) {
    if (i) j += ",";
    j += "\"" + jesc(customAllow[i]) + "\"";
  }
  j += "]}";
  web.send(200, "application/json", j);
}

static void handleDiag() {
  String body = "";
  const AdbStats& s = adb.stats();
  uint32_t total = s.blocked + s.forwarded;
  double rate = total ? (double)s.blocked * 100.0 / total : 0.0;

  struct Chk { bool ok; const char* name; String detail; };
  Chk list[] = {
      {adb.ready(), "规则包已加载", adb.diagnose()},
      {adb.ruleCount() > 100000, "规则数量充足", String(adb.ruleCount()) + " 条"},
      {upstreamHealthy, "上游 DNS 可达", upstreamHealthy ? String("正常") : String("不通，已自动放行")},
      {numClients > 0, "有客户端在查询", String(numClients) + " 台"},
      {s.blocked > 0, "已产生拦截", String(s.blocked) + " 次"},
      {rate >= 3.0, "拦截占比合理", String(rate, 1) + "%（正常 8%~25%，0% 说明路由器没接管）"},
  };
  for (size_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
    if (body.length()) body += ",";
    body += "{\"ok\":";
    body += list[i].ok ? "true" : "false";
    body += ",\"name\":\"" + jesc(String(list[i].name)) + "\",\"detail\":\"" + jesc(list[i].detail) + "\"}";
  }
  web.send(200, "application/json", "{\"checks\":[" + body + "]}");
}

static void handleInfo() {
  String j = "{";
  j += "\"sn\":\"" + String(deviceSn) + "\",";
  j += "\"fw\":\"" FW_VERSION "\",";
  j += "\"rules\":" + String(adb.ruleCount()) + ",";
  j += "\"ip\":\"" + WiFi.localIP().toString() + "\",";
  j += "\"mac\":\"" + WiFi.macAddress() + "\",";
  j += "\"rssi\":" + String(WiFi.RSSI()) + ",";
  j += "\"heap\":" + String(ESP.getFreeHeap()) + ",";
  j += "\"psram\":" + String(ESP.getFreePsram()) + "}";
  web.send(200, "application/json", j);
}

static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE = "adblock";

static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) {
    web.send(403, "text/plain", "missing CSRF header");
    return false;
  }
  if (web.authenticate(WEB_USER, WEB_PASS)) return true;
  web.requestAuthentication();
  return false;
}

// ---------------- 规则包 / 固件上传 ----------------
static bool fwAuthOk = false;
static bool upAuthOk = false;
static File upFile;

static bool swapRules() {
  if (upFile) upFile.close();
  File f = LittleFS.open(RULE_PATH_NEW, "r");
  if (!f) return false;
  size_t sz = f.size();
  uint8_t hdr[6];
  memset(hdr, 0, sizeof(hdr));
  f.read(hdr, 6);
  f.close();

  bool looksV2 = memcmp(hdr, RULE_MAGIC, 4) == 0;
  bool looksV1 = sz > 1000 && (sz % HASH_BYTES) == 0;
  if (!looksV2 && !looksV1) {
    LittleFS.remove(RULE_PATH_NEW);
    Serial.println("[rules] rejected: bad magic/size");
    return false;
  }
  LittleFS.remove(RULE_PATH);
  if (!LittleFS.rename(RULE_PATH_NEW, RULE_PATH)) return false;
  adb.begin();
  Serial.printf("[rules] loaded %u entries\n", adb.ruleCount());
  return adb.ready();
}

static void handleRulesUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    upAuthOk = (web.header(CSRF_HEADER) == CSRF_VALUE) && web.authenticate(WEB_USER, WEB_PASS);
    if (!upAuthOk) return;
    LittleFS.remove(RULE_PATH_NEW);
    upFile = LittleFS.open(RULE_PATH_NEW, "w");
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (upAuthOk && upFile) upFile.write(u.buf, u.currentSize);
  } else if (u.status == UPLOAD_FILE_END) {
    if (upAuthOk) swapRules();
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (upFile) upFile.close();
    LittleFS.remove(RULE_PATH_NEW);
  }
}

static void handleRulesDone() {
  if (!upAuthOk) {
    web.requestAuthentication();
    return;
  }
  bool ok = adb.ready();
  String msg = ok ? ("ok " + String(adb.ruleCount()) + " rules") : String("invalid blocklist");
  web.send(ok ? 200 : 500, "text/plain", msg);
}

static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = (web.header(CSRF_HEADER) == CSRF_VALUE) && web.authenticate(WEB_USER, WEB_PASS);
    if (!fwAuthOk) return;
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (fwAuthOk) Update.write(u.buf, u.currentSize);
  } else if (u.status == UPLOAD_FILE_END) {
    if (fwAuthOk) Update.end(true);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (fwAuthOk) Update.abort();
  }
}

static void handleFwDone() {
  if (!fwAuthOk) {
    web.requestAuthentication();
    return;
  }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) {
    delay(300);
    ESP.restart();
  }
}

// ---------------- 配网 ----------------
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();

  const char* sid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pwd = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!sid || !*sid || strcmp(sid, "YOUR_WIFI_SSID") == 0) return false;

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(sid, pwd);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) delay(250);
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html = "<!doctype html><meta charset=utf-8>";
  html += "<meta name=viewport content='width=device-width,initial-scale=1'>";
  html += "<title>AdBlock Setup</title>";
  html += "<body style='font:16px system-ui;max-width:420px;margin:32px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>";
  html += "<h2>WiFi Setup</h2>";
  html += "<p style='color:#8b949e'>Pick your WiFi and enter the password.</p>";
  html += "<form method=POST action=/wifisave>";
  html += "<input name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>";
  html += "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>";
  html += "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600'>Connect</button>";
  html += "</form></body>";
  web.send(200, "text/html", html);
}

static void handleWifiSave() {
  String ss = web.arg("s");
  String pw = web.arg("p");
  if (!ss.length()) {
    web.send(400, "text/plain", "missing ssid");
    return;
  }
  prefs.begin("wifi", false);
  prefs.putString("ssid", ss);
  prefs.putString("pass", pw);
  prefs.end();

  String ok = "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>";
  ok += "Saved. Joining <b>" + htmlEscape(ss) + "</b>...";
  ok += "<br><br>Reconnect your phone to your normal WiFi, then open the device IP.</body>";
  web.send(200, "text/html", ok);
  delay(900);
  ESP.restart();
}

// 永不返回
static void startConfigPortal() {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  char ap[28];
  snprintf(ap, sizeof(ap), "AdBlock-%02X%02X", mac[4], mac[5]);

  WiFi.mode(WIFI_AP);
  WiFi.softAP(ap);
  IPAddress apIp = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIp);

  web.on("/", HTTP_GET, handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound([]() { handlePortalRoot(); });
  web.begin();

  Serial.printf("[setup] AP \"%s\" -> http://%s\n", ap, apIp.toString().c_str());
  while (true) {
    dnsPortal.processNextRequest();
    web.handleClient();
    delay(2);
  }
}

// ---------------- setup / loop ----------------
void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println();
  Serial.println("[adblock] boot " FW_VERSION);
  Serial.printf("chip=%s flash=%uMB psram=%uKB\n", ESP.getChipModel(),
                (unsigned)(ESP.getFlashChipSize() / 1048576), (unsigned)(ESP.getPsramSize() / 1024));

  if (!LittleFS.begin(true)) Serial.println("[fs] LittleFS mount failed");

  loadCustomAllow();
  loadDeviceId();
  adb.begin();
  Serial.printf("[rules] %u entries | %s\n", adb.ruleCount(), adb.diagnose().c_str());
  if (!adb.ready()) Serial.println("[rules] WARNING: no blocklist, running as plain DNS forwarder");

#if CONFIG_IDF_TARGET_ESP32C3
  const int BOOT_PIN = 9;
#else
  const int BOOT_PIN = 0;
#endif
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) {
    delay(60);
    if (digitalRead(BOOT_PIN) == LOW) {
      prefs.begin("wifi", false);
      prefs.clear();
      prefs.end();
      Serial.println("[setup] BOOT held, WiFi credentials cleared");
    }
  }

  if (!connectWiFi()) startConfigPortal();

  Serial.printf("[wifi] %s rssi=%d\n", WiFi.localIP().toString().c_str(), WiFi.RSSI());
  if (MDNS.begin("adblock")) MDNS.addService("http", "tcp", 80);

  dnsServer.begin(DNS_PORT);
  upstreamCli.begin(0);

  const char* hdrs[] = {CSRF_HEADER};
  web.collectHeaders(hdrs, 1);

  web.on("/", HTTP_GET, []() {
    static const char PAGE[] =
        "<!doctype html><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>AdBlock</title>"
        "<body style='font:15px/1.6 system-ui;max-width:660px;margin:24px auto;padding:0 16px'>"
        "<h2>AdBlock " FW_VERSION "</h2>"
        "<p><a href=/stats.json>stats.json</a> &middot; <a href=/diag.json>diag.json</a> "
        "&middot; <a href=/info.json>info.json</a></p>"
        "<pre id=o style='background:#f6f8fa;padding:12px;border-radius:8px;white-space:pre-wrap'></pre>"
        "<script>"
        "fetch('/diag.json').then(function(r){return r.json()}).then(function(d){"
        "var t=d.checks.map(function(c){return (c.ok?'[OK] ':'[NG] ')+c.name+' - '+c.detail}).join('\\n');"
        "document.getElementById('o').textContent=t;});"
        "</script></body>";
    web.send_P(200, "text/html", PAGE);
  });
  web.on("/stats.json", HTTP_GET, handleStats);
  web.on("/diag.json", HTTP_GET, handleDiag);
  web.on("/info.json", HTTP_GET, handleInfo);
  web.on("/upload", HTTP_POST, handleRulesDone, handleRulesUpload);
  web.on("/update", HTTP_POST, handleFwDone, handleFwUpload);

  web.on("/allow", HTTP_GET, []() {
    if (!requireAuth()) return;
    String d = web.arg("d");
    d.trim();
    d.toLowerCase();
    if (d.length() > 3 && d.indexOf('.') > 0 && numCustomAllow < MAX_CUSTOM_ALLOW) {
      customAllow[numCustomAllow++] = d;
      saveCustomAllow();
      web.send(200, "text/plain", "allowlisted " + d);
    } else {
      web.send(400, "text/plain", "bad domain");
    }
  });
  web.on("/pause", HTTP_GET, []() {
    if (!requireAuth()) return;
    blockingOn = false;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", HTTP_GET, []() {
    if (!requireAuth()) return;
    blockingOn = true;
    web.send(200, "text/plain", "resumed");
  });
  web.begin();

  ArduinoOTA.setHostname("adblock");
  ArduinoOTA.setPassword(OTA_PASS);
  ArduinoOTA.begin();

  Serial.printf("[ready] DNS :53  web :80  rules=%u\n", adb.ruleCount());
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  handleDns();
  probeUpstream();
  delay(1);
}

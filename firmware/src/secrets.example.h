// secrets.h — 本地私密配置（已在 .gitignore 中排除，不会进仓库）
// 首次使用：复制 secrets.example.h 为 secrets.h，改掉里面的值。
#pragma once

// Web 后台 Basic Auth（统计/规则上传/固件升级都要过这一关）
#define WEB_USER "admin"
#define WEB_PASS "CHANGE_ME_WEB_PASS"

// ArduinoOTA 升级口令
#define OTA_PASS "CHANGE_ME_OTA_PASS"

// 默认 WiFi（配网页面保存后会覆盖它；留空则强制进配网 AP 模式）
#define WIFI_SSID "YOUR_WIFI_SSID"
#define WIFI_PASS "YOUR_WIFI_PASS"

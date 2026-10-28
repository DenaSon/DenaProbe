#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include "wifi_config.h"

// Optional local-only settings. Never commit include/probe_private.h.
#if __has_include("probe_private.h")
#include "probe_private.h"
#else
#define PROBE_EDGE_HOST "CHANGE_ME_EDGE_HOST"
#define PROBE_EDGE_PORT 2252
#endif

// Phase 1B / observation only. No authentication, VPN, or censorship verdict.
namespace {
constexpr uint32_t kReportIntervalMs = 5000;
constexpr uint32_t kRetryIntervalMs = 20000;
constexpr uint32_t kProbeIntervalMs = 60000;
constexpr int32_t kTcpTimeoutMs = 4000;
constexpr uint32_t kBannerTimeoutMs = 4000;
constexpr size_t kMaxBannerLength = 160;

uint32_t lastAttemptMs = 0;
uint32_t lastReportMs = 0;
uint32_t lastProbeMs = 0;
wl_status_t lastStatus = WL_IDLE_STATUS;
bool validWifiConfig = false;
bool validProbeConfig = false;
bool probeDue = false;

void beginConnection() {
    Serial.printf("[wifi] Connecting to SSID: %s\n", WIFI_SSID);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    lastAttemptMs = millis();
}

void printConnectionDetails() {
    Serial.print("[wifi] IP: ");
    Serial.println(WiFi.localIP());
    Serial.print("[wifi] Gateway: ");
    Serial.println(WiFi.gatewayIP());
    Serial.print("[wifi] DNS: ");
    Serial.println(WiFi.dnsIP());
    Serial.printf("[wifi] RSSI: %d dBm\n", WiFi.RSSI());
}

void runNetworkProbe() {
    if (!validProbeConfig || WiFi.status() != WL_CONNECTED) return;

    const unsigned long startedAt = millis();
    Serial.printf("[probe] START | uptime_ms=%lu | RSSI=%d dBm | edge_port=%u\n",
                  startedAt, WiFi.RSSI(), static_cast<unsigned>(PROBE_EDGE_PORT));

    IPAddress ip;
    const unsigned long dnsStart = millis();
    const bool dnsOk = WiFi.hostByName(PROBE_EDGE_HOST, ip) == 1;
    const unsigned long dnsDuration = millis() - dnsStart;
    if (!dnsOk) {
        Serial.printf("[dns] FAIL | elapsed_ms=%lu\n", dnsDuration);
        Serial.println("[probe] END | stage=DNS_FAIL | no_filtering_verdict");
        return;
    }
    Serial.printf("[dns] PASS | elapsed_ms=%lu | edge_ip=%s\n",
                  dnsDuration, ip.toString().c_str());

    WiFiClient client;
    const unsigned long tcpStart = millis();
    const bool tcpOk = client.connect(ip, static_cast<uint16_t>(PROBE_EDGE_PORT), kTcpTimeoutMs);
    const unsigned long tcpDuration = millis() - tcpStart;
    if (!tcpOk) {
        Serial.printf("[tcp] FAIL | elapsed_ms=%lu\n", tcpDuration);
        Serial.println("[probe] END | stage=TCP_FAIL | no_filtering_verdict");
        client.stop();
        return;
    }
    Serial.printf("[tcp] PASS | elapsed_ms=%lu\n", tcpDuration);

    // Wait for the SSH identification line. No user/password, KEX, or tunnel.
    const unsigned long bannerStart = millis();
    char line[kMaxBannerLength] = {};
    size_t lineLength = 0;
    bool bannerOk = false;
    bool gotOtherLine = false;
    bool ended = false;

    while (millis() - bannerStart < kBannerTimeoutMs && !ended) {
        while (client.available() > 0) {
            const int incoming = client.read();
            if (incoming < 0) break;
            const char ch = static_cast<char>(incoming);
            if (ch == '\r') continue;

            if (ch == '\n') {
                line[lineLength] = '\0';
                if (strncmp(line, "SSH-2.0-", 8) == 0) {
                    bannerOk = true;
                    ended = true;
                    break;
                }
                gotOtherLine = true; // An SSH server may send pre-banner notices.
                lineLength = 0;
            } else if (lineLength < kMaxBannerLength - 1) {
                line[lineLength++] = ch;
            } else {
                ended = true; // Unexpectedly long/invalid identification line.
                break;
            }
        }
        if (ended || !client.connected()) break;
        delay(10);
    }

    const unsigned long bannerDuration = millis() - bannerStart;
    if (bannerOk) {
        Serial.printf("[ssh-id] PASS | elapsed_ms=%lu | protocol=SSH-2.0\n", bannerDuration);
        Serial.println("[probe] END | stage=SSH_ID_PASS | no_filtering_verdict");
    } else {
        Serial.printf("[ssh-id] FAIL | elapsed_ms=%lu | prebanner=%s | socket_open=%s\n",
                      bannerDuration, gotOtherLine ? "yes" : "no",
                      client.connected() ? "yes" : "no");
        Serial.println("[probe] END | stage=SSH_ID_FAIL | no_filtering_verdict");
    }
    client.stop();
}
} // namespace

void setup() {
    Serial.begin(115200);
    delay(1500);
    Serial.println();
    Serial.println("=== DenaProbe | DNS/TCP/SSH-ID Probe v0.0.3 ===");
    Serial.printf("Chip: %s | CPU: %u MHz | Flash: %u bytes\n",
                  ESP.getChipModel(), ESP.getCpuFreqMHz(), ESP.getFlashChipSize());

    validWifiConfig = strcmp(WIFI_SSID, "CHANGE_ME_HOTSPOT_SSID") != 0 &&
                      strlen(WIFI_SSID) > 0;
    validProbeConfig = strcmp(PROBE_EDGE_HOST, "CHANGE_ME_EDGE_HOST") != 0 &&
                       strlen(PROBE_EDGE_HOST) > 0 && PROBE_EDGE_PORT > 0 &&
                       PROBE_EDGE_PORT <= 65535;

    if (!validWifiConfig) {
        Serial.println("[config] ERROR: Set WIFI_SSID in include/wifi_config.h");
        return;
    }
    if (!validProbeConfig) {
        Serial.println("[config] Probe disabled: configure include/probe_private.h locally.");
    }

    WiFi.mode(WIFI_STA);
    WiFi.setAutoReconnect(false);
    beginConnection();
}

void loop() {
    if (!validWifiConfig) {
        delay(1000);
        return;
    }

    const uint32_t nowMs = millis();
    const wl_status_t status = WiFi.status();

    if (status != lastStatus) {
        Serial.printf("[wifi] Status: %d -> %d\n",
                      static_cast<int>(lastStatus), static_cast<int>(status));
        if (status == WL_CONNECTED) {
            Serial.println("[wifi] CONNECTED");
            printConnectionDetails();
            probeDue = true;
        } else if (lastStatus == WL_CONNECTED) {
            Serial.println("[wifi] DISCONNECTED");
            probeDue = false;
        }
        lastStatus = status;
    }

    if (nowMs - lastReportMs >= kReportIntervalMs) {
        lastReportMs = nowMs;
        if (status == WL_CONNECTED) {
            Serial.printf("[wifi] OK | uptime=%lu s | RSSI=%d dBm | free_heap=%u\n",
                          static_cast<unsigned long>(nowMs / 1000),
                          WiFi.RSSI(), ESP.getFreeHeap());
        } else {
            Serial.printf("[wifi] WAITING | uptime=%lu s | status=%d\n",
                          static_cast<unsigned long>(nowMs / 1000),
                          static_cast<int>(status));
        }
    }

    if (status == WL_CONNECTED && validProbeConfig &&
        (probeDue || nowMs - lastProbeMs >= kProbeIntervalMs)) {
        probeDue = false;
        lastProbeMs = millis();
        runNetworkProbe();
    }

    if (status != WL_CONNECTED && nowMs - lastAttemptMs >= kRetryIntervalMs) {
        Serial.println("[wifi] Retry after 20 seconds without connection");
        WiFi.disconnect();
        beginConnection();
    }
    delay(100);
}

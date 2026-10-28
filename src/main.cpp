#include <Arduino.h>
#include <WiFi.h>
#include "wifi_config.h"

// Phase 1 / Wi-Fi link validation ONLY.
// No DNS, external network probes, filtering detection, or SIM800L.
namespace {
constexpr uint32_t kReportIntervalMs = 5000;
constexpr uint32_t kRetryIntervalMs = 20000;
uint32_t lastAttemptMs = 0;
uint32_t lastReportMs = 0;
wl_status_t lastStatus = WL_IDLE_STATUS;
bool validConfig = false;

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
} // namespace

void setup() {
    Serial.begin(115200);
    delay(1500);
    Serial.println();
    Serial.println("=== DenaProbe | Wi-Fi Link Test v0.0.2 ===");
    Serial.printf("Chip: %s | CPU: %u MHz | Flash: %u bytes\n",
                  ESP.getChipModel(), ESP.getCpuFreqMHz(), ESP.getFlashChipSize());

    validConfig = strcmp(WIFI_SSID, "CHANGE_ME_HOTSPOT_SSID") != 0 &&
                  strlen(WIFI_SSID) > 0;
    if (!validConfig) {
        Serial.println("[config] ERROR: Set WIFI_SSID in include/wifi_config.h");
        return;
    }

    WiFi.mode(WIFI_STA);
    WiFi.setAutoReconnect(false); // Use a controlled retry schedule for test logs.
    beginConnection();
}

void loop() {
    if (!validConfig) {
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
        } else if (lastStatus == WL_CONNECTED) {
            Serial.println("[wifi] DISCONNECTED");
        }
        lastStatus = status;
    }

    if (nowMs - lastReportMs >= kReportIntervalMs) {
        lastReportMs = nowMs;
        if (status == WL_CONNECTED) {
            Serial.printf("[wifi] OK | uptime=%lu s | RSSI=%d dBm | free_heap=%u\n",
                          static_cast<unsigned long>(nowMs / 1000), WiFi.RSSI(), ESP.getFreeHeap());
        } else {
            Serial.printf("[wifi] WAITING | uptime=%lu s | status=%d\n",
                          static_cast<unsigned long>(nowMs / 1000), static_cast<int>(status));
        }
    }

    if (status != WL_CONNECTED && nowMs - lastAttemptMs >= kRetryIntervalMs) {
        Serial.println("[wifi] Retry after 20 seconds without connection");
        WiFi.disconnect();
        beginConnection();
    }
    delay(100);
}

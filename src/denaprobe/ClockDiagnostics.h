#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <cstdint>

// R1 diagnostics only. This does not set time from a fallback source or
// bypass HTTPS certificate verification. DNS resolution is NOT a UDP/123 test.
namespace DenaProbe {
class ClockDiagnostics {
public:
    static constexpr int64_t kMinTlsEpoch = 1700000000LL;

    // Called from the Arduino loop. Never start the blocking DNS diagnostics
    // while an SSH/HTTPS crypto worker is active.
    void update(uint32_t now, bool wifiUp, bool ipv4Ready,
                int64_t epoch, bool workerBusy) {
        if (!wifiUp || !ipv4Ready) {
            if (configured_) {
                Serial.println("[clock] state=LINK_DOWN_OR_NO_IP | sntp=WAITING_FOR_IP | "
                               "udp123=NOT_TESTED");
                configured_ = false;
                hasReport_ = false;
            }
            return;
        }
        if (!configured_) {
            if (workerBusy) return;
            // Start only AFTER the hotspot connection and IPv4 assignment.
            configTime(0, 0, "time.cloudflare.com", "pool.ntp.org");
            configured_ = true;
            Serial.printf("[clock] sntp=STARTED | after_ipv4=1 | boot_ms=%lu | "
                          "servers=time.cloudflare.com,pool.ntp.org | "
                          "udp123=UNVERIFIED\n",
                          static_cast<unsigned long>(now));
            logDns("time.cloudflare.com");
            if (WiFi.status() == WL_CONNECTED) logDns("pool.ntp.org");
            report(millis(), epoch);
            return;
        }
        const bool ready = epoch >= kMinTlsEpoch;
        if (!hasReport_ || ready != lastReady_ ||
            static_cast<uint32_t>(now - lastReportMs_) >=
                (ready ? 60000U : 10000U)) {
            report(now, epoch);
        }
    }

private:
    void logDns(const char *host) {
        IPAddress resolved;
        const uint32_t start = millis();
        const bool ok = WiFi.hostByName(host, resolved) == 1;
        const uint32_t elapsed = millis() - start;
        const bool linkUp = WiFi.status() == WL_CONNECTED;
        Serial.printf("[clock-dns] host=%s | result=%s | dns_ms=%lu | "
                      "wifi=%s | udp123=NOT_TESTED\n",
                      host, linkUp ? (ok ? "PASS" : "FAIL") : "UNMEASURABLE",
                      static_cast<unsigned long>(elapsed),
                      linkUp ? "UP" : "DOWN");
    }

    void report(uint32_t now, int64_t epoch) {
        const bool ready = epoch >= kMinTlsEpoch;
        Serial.printf("[clock] sntp=STARTED | epoch=%lld | ready=%s | "
                      "boot_ms=%lu | udp123=UNVERIFIED | "
                      "tls_verify=REQUIRED\n",
                      static_cast<long long>(epoch), ready ? "YES" : "NO",
                      static_cast<unsigned long>(now));
        hasReport_ = true;
        lastReady_ = ready;
        lastReportMs_ = now;
    }

    bool configured_ = false;
    bool hasReport_ = false;
    bool lastReady_ = false;
    uint32_t lastReportMs_ = 0;
};
} // namespace DenaProbe

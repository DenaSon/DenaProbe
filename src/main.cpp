#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>
#include "wifi_config.h"

// Optional HTTPS reporting. Builds and runs safely without a report token.
#if __has_include("probe_report_private.h")
#include "probe_report_private.h"
#define DENAPROBE_REPORTING_ENABLED 1
#else
#define DENAPROBE_REPORTING_ENABLED 0
#endif

// All private infrastructure configuration stays on the local machine.
#if __has_include("probe_private.h")
#include "probe_private.h"
#else
#define PROBE_EDGE_HOST "CHANGE_ME_EDGE_HOST"
#define PROBE_EDGE_PORT 2252
#endif

// ESP32 DevKit commonly connects its onboard LED to GPIO2, but some boards
// use a different pin, reverse polarity, or have no software-controlled LED.
#ifndef PROBE_LED_PIN
#define PROBE_LED_PIN 2
#endif
#ifndef PROBE_LED_ACTIVE_LOW
#define PROBE_LED_ACTIVE_LOW 0
#endif

// v0.0.5: observational Edge checks, blue LED and OPTIONAL signed-in HTTPS reporting
// and status LED. No SSH authentication, Core address, or filtering verdict.
namespace {
constexpr uint32_t kReportIntervalMs = 5000;
constexpr uint32_t kRetryIntervalMs = 20000;
constexpr uint32_t kProbeIntervalMs = 60000;
constexpr int32_t kTcpTimeoutMs = 4000;
constexpr uint32_t kBannerTimeoutMs = 4000;
constexpr int32_t kControlTcpTimeoutMs = 3000;
constexpr size_t kMaxBannerLength = 160;
constexpr const char* kPublicControlHost = "example.com";
constexpr uint16_t kPublicControlPort = 443;
constexpr uint8_t kPersistentThreshold = 3;

struct ProbeSample {
    uint32_t uptimeMs = 0;
    int rssi = -100;
    int dnsOk = -1;
    int dnsMs = -1;
    int tcpOk = -1;
    int tcpMs = -1;
    int sshOk = -1;
    int sshMs = -1;
    int controlOk = -1;
    int controlMs = -1;
    IPAddress edgeIp;
};

enum class LedMode : uint8_t {
    WIFI_WAIT,  // 1 s ON + 1 s OFF
    HEALTHY,    // steady ON
    SUSPECT,    // two short flashes per 2 seconds
    EDGE_ISSUE  // fast blinking: 125 ms ON + 125 ms OFF
};

enum class EdgeResult : uint8_t {
    SSH_ID_PASS,
    DNS_FAIL,
    TCP_FAIL,
    SSH_ID_FAIL
};

uint32_t lastAttemptMs = 0;
uint32_t lastReportMs = 0;
uint32_t lastProbeMs = 0;
wl_status_t lastStatus = WL_IDLE_STATUS;
bool validWifiConfig = false;
bool validProbeConfig = false;
bool probeDue = false;
uint8_t consecutiveEdgeFailures = 0;
LedMode ledMode = LedMode::WIFI_WAIT;
int lastLedOutput = -1;
IPAddress lastEdgeIP;
bool havePreviousEdgeIP = false;

const char* ledModeName(LedMode mode) {
    switch (mode) {
        case LedMode::WIFI_WAIT: return "WIFI_WAIT";
        case LedMode::HEALTHY: return "HEALTHY";
        case LedMode::SUSPECT: return "SUSPECT";
        case LedMode::EDGE_ISSUE: return "EDGE_ISSUE";
    }
    return "UNKNOWN";
}

const char* resultName(EdgeResult result) {
    switch (result) {
        case EdgeResult::SSH_ID_PASS: return "SSH_ID_PASS";
        case EdgeResult::DNS_FAIL: return "DNS_FAIL";
        case EdgeResult::TCP_FAIL: return "TCP_FAIL";
        case EdgeResult::SSH_ID_FAIL: return "SSH_ID_FAIL";
    }
    return "UNKNOWN";
}

void setLedMode(LedMode next) {
    if (next != ledMode) {
        ledMode = next;
        Serial.printf("[led] mode=%s | gpio=%u | active_low=%u\n",
                      ledModeName(ledMode), static_cast<unsigned>(PROBE_LED_PIN),
                      static_cast<unsigned>(PROBE_LED_ACTIVE_LOW));
    }
}

void updateLed(uint32_t nowMs) {
    bool ledOn = false;
    switch (ledMode) {
        case LedMode::WIFI_WAIT:
            ledOn = (nowMs % 2000U) < 1000U;
            break;
        case LedMode::HEALTHY:
            ledOn = true;
            break;
        case LedMode::SUSPECT: {
            const uint32_t phase = nowMs % 2000U;
            ledOn = phase < 120U || (phase >= 320U && phase < 440U);
            break;
        }
        case LedMode::EDGE_ISSUE:
            ledOn = (nowMs % 250U) < 125U;
            break;
    }

    const int output = ledOn ? (PROBE_LED_ACTIVE_LOW ? LOW : HIGH)
                             : (PROBE_LED_ACTIVE_LOW ? HIGH : LOW);
    if (output != lastLedOutput) {
        digitalWrite(PROBE_LED_PIN, output);
        lastLedOutput = output;
    }
}

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

// Independent control of DNS resolution and PUBLIC TCP:443 reachability;
// not HTTPS/TLS or proof that the whole Internet is working.
bool checkPublicTcpControl(ProbeSample* sample) {
    IPAddress controlIp;
    const uint32_t dnsStart = millis();
    const bool dnsOk = WiFi.hostByName(kPublicControlHost, controlIp) == 1;
    const uint32_t dnsMs = millis() - dnsStart;
    if (!dnsOk) {
        sample->controlOk = 0;
        sample->controlMs = static_cast<int>(dnsMs);
        Serial.printf("[control] FAIL | type=PUBLIC_TCP_443 | stage=DNS | elapsed_ms=%lu\n",
                      static_cast<unsigned long>(dnsMs));
        return false;
    }

    WiFiClient client;
    const uint32_t tcpStart = millis();
    const bool tcpOk = client.connect(controlIp, kPublicControlPort, kControlTcpTimeoutMs);
    const uint32_t tcpMs = millis() - tcpStart;
    client.stop();
    sample->controlOk = tcpOk ? 1 : 0;
    sample->controlMs = static_cast<int>(tcpMs);
    Serial.printf("[control] %s | type=PUBLIC_TCP_443 | dns_ms=%lu | tcp_ms=%lu\n",
                  tcpOk ? "PASS" : "FAIL",
                  static_cast<unsigned long>(dnsMs),
                  static_cast<unsigned long>(tcpMs));
    return tcpOk;
}

EdgeResult runEdgeProbe(ProbeSample* sample) {
    const unsigned long startedAt = millis();
    sample->uptimeMs = static_cast<uint32_t>(startedAt);
    sample->rssi = WiFi.RSSI();
    Serial.printf("[probe] START | uptime_ms=%lu | RSSI=%d dBm | edge_port=%u\n",
                  startedAt, WiFi.RSSI(), static_cast<unsigned>(PROBE_EDGE_PORT));

    // Resolve the hostname on EACH cycle; never pin an Edge IP in firmware.
    IPAddress ip;
    const unsigned long dnsStart = millis();
    const bool dnsOk = WiFi.hostByName(PROBE_EDGE_HOST, ip) == 1;
    const unsigned long dnsDuration = millis() - dnsStart;
    sample->dnsOk = dnsOk ? 1 : 0;
    sample->dnsMs = static_cast<int>(dnsDuration);
    if (!dnsOk) {
        Serial.printf("[dns] FAIL | elapsed_ms=%lu\n", dnsDuration);
        Serial.println("[probe] END | stage=DNS_FAIL | no_filtering_verdict");
        return EdgeResult::DNS_FAIL;
    }
    Serial.printf("[dns] PASS | elapsed_ms=%lu | edge_ip=%s\n",
                  dnsDuration, ip.toString().c_str());
    if (havePreviousEdgeIP && ip != lastEdgeIP) {
        Serial.println("[dns] EDGE_IP_CHANGED | DNS answer differs from previous cycle");
    }
    lastEdgeIP = ip;
    havePreviousEdgeIP = true;
    sample->edgeIp = ip;

    WiFiClient client;
    const unsigned long tcpStart = millis();
    const bool tcpOk = client.connect(
        ip, static_cast<uint16_t>(PROBE_EDGE_PORT), kTcpTimeoutMs);
    const unsigned long tcpDuration = millis() - tcpStart;
    sample->tcpOk = tcpOk ? 1 : 0;
    sample->tcpMs = static_cast<int>(tcpDuration);
    if (!tcpOk) {
        Serial.printf("[tcp] FAIL | elapsed_ms=%lu\n", tcpDuration);
        Serial.println("[probe] END | stage=TCP_FAIL | no_filtering_verdict");
        client.stop();
        return EdgeResult::TCP_FAIL;
    }
    Serial.printf("[tcp] PASS | elapsed_ms=%lu\n", tcpDuration);

    // Passive SSH identification: neither sends a password nor establishes a VPN.
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
                gotOtherLine = true;
                lineLength = 0;
            } else if (lineLength < kMaxBannerLength - 1) {
                line[lineLength++] = ch;
            } else {
                ended = true;
                break;
            }
        }
        if (ended || !client.connected()) break;
        updateLed(millis());
        delay(10);
    }

    const unsigned long bannerDuration = millis() - bannerStart;
    sample->sshOk = bannerOk ? 1 : 0;
    sample->sshMs = static_cast<int>(bannerDuration);
    if (bannerOk) {
        Serial.printf("[ssh-id] PASS | elapsed_ms=%lu | protocol=SSH-2.0\n",
                      bannerDuration);
        Serial.println("[probe] END | stage=SSH_ID_PASS | no_filtering_verdict");
    } else {
        Serial.printf("[ssh-id] FAIL | elapsed_ms=%lu | prebanner=%s | socket_open=%s\n",
                      bannerDuration, gotOtherLine ? "yes" : "no",
                      client.connected() ? "yes" : "no");
        Serial.println("[probe] END | stage=SSH_ID_FAIL | no_filtering_verdict");
    }
    client.stop();
    return bannerOk ? EdgeResult::SSH_ID_PASS : EdgeResult::SSH_ID_FAIL;
}


#if DENAPROBE_REPORTING_ENABLED
constexpr size_t kReportQueueCapacity = 8;
String reportQueue[kReportQueueCapacity];
size_t reportHead = 0;
size_t reportCount = 0;
uint32_t reportSequence = 0;
char reportBootId[9] = {};

String nullableNumber(int value) {
    return value < 0 ? String("null") : String(value);
}

const char* nullableBoolean(int value) {
    return value < 0 ? "null" : (value ? "true" : "false");
}

void initializeReporting() {
    snprintf(reportBootId, sizeof(reportBootId), "%08lx",
             static_cast<unsigned long>(esp_random()));
    if (strlen(PROBE_REPORT_TOKEN) < 32 ||
        strlen(PROBE_REPORT_CA_PEM) < 100 ||
        strcmp(PROBE_REPORT_DEVICE_ID, "probe_01") == 0 &&
            strcmp(PROBE_REPORT_TOKEN, "REPLACE_WITH_RANDOM_64_HEX_CHARS") == 0) {
        Serial.println("[telemetry] DISABLED | configure valid token and CA PEM");
    } else {
        Serial.println("[telemetry] CONFIGURED | HTTPS strict CA validation; awaiting NTP");
    }
}

bool reportingConfigValid() {
    return strlen(PROBE_REPORT_TOKEN) >= 32 && strlen(PROBE_REPORT_CA_PEM) >= 100
           && strncmp(PROBE_REPORT_CA_PEM, "\n-----BEGIN CERTIFICATE-----", 28) == 0
           && strcmp(PROBE_REPORT_TOKEN, "REPLACE_WITH_RANDOM_64_HEX_CHARS") != 0;
}

void enqueueSample(const ProbeSample& sample) {
    if (!reportingConfigValid()) return;
    const uint32_t seq = ++reportSequence;
    String report;
    report.reserve(520);
    report = "{\"schema_version\":1,\"device_id\":\"";
    report += PROBE_REPORT_DEVICE_ID;
    report += "\",\"boot_id\":\"";
    report += reportBootId;
    report += "\",\"sequence\":";
    report += String(seq);
    report += ",\"uptime_ms\":";
    report += String(sample.uptimeMs);
    report += ",\"edge_host\":\"";
    report += PROBE_EDGE_HOST;
    report += "\",\"edge_ipv4\":";
    if (sample.dnsOk == 1) {
        report += "\"";
        report += sample.edgeIp.toString();
        report += "\"";
    } else report += "null";
    report += ",\"edge_port\":";
    report += String(PROBE_EDGE_PORT);
    report += ",\"carrier_declared\":\"";
    report += PROBE_CARRIER_DECLARED;
    report += "\",\"wifi_rssi_dbm\":";
    report += String(sample.rssi);
    report += ",\"dns_ok\":";
    report += nullableBoolean(sample.dnsOk);
    report += ",\"dns_ms\":";
    report += nullableNumber(sample.dnsMs);
    report += ",\"tcp_ok\":";
    report += nullableBoolean(sample.tcpOk);
    report += ",\"tcp_ms\":";
    report += nullableNumber(sample.tcpMs);
    report += ",\"ssh_id_ok\":";
    report += nullableBoolean(sample.sshOk);
    report += ",\"ssh_id_ms\":";
    report += nullableNumber(sample.sshMs);
    report += ",\"control_ok\":";
    report += nullableBoolean(sample.controlOk);
    report += ",\"control_ms\":";
    report += nullableNumber(sample.controlMs);
    report += "}";

    if (reportCount >= kReportQueueCapacity) {
        reportHead = (reportHead + 1) % kReportQueueCapacity;
        --reportCount;
        Serial.println("[telemetry] QUEUE_OVERFLOW | oldest report dropped");
    }
    const size_t tail = (reportHead + reportCount) % kReportQueueCapacity;
    reportQueue[tail] = report;
    ++reportCount;
}

void flushReports() {
    if (!reportingConfigValid() || WiFi.status() != WL_CONNECTED || !reportCount) return;
    if (time(nullptr) < 1700000000) {
        Serial.println("[telemetry] DEFERRED | clock not synchronized for TLS");
        return;
    }
    const String url = String("https://") + PROBE_REPORT_HOST + PROBE_REPORT_PATH;
    for (int attempt = 0; attempt < 2 && reportCount; ++attempt) {
        WiFiClientSecure client;
        client.setCACert(PROBE_REPORT_CA_PEM); // No setInsecure() fallback.
        HTTPClient http;
        http.setTimeout(5000);
        if (!http.begin(client, url)) {
            Serial.println("[telemetry] DEFERRED | HTTPS begin failed");
            return;
        }
        http.addHeader("Content-Type", "application/json");
        http.addHeader("X-DenaProbe-Device", PROBE_REPORT_DEVICE_ID);
        http.addHeader("Authorization", String("Bearer ") + PROBE_REPORT_TOKEN);
        const int status = http.POST(reportQueue[reportHead]);
        http.end();
        if (status != 200) {
            Serial.printf("[telemetry] DEFERRED | HTTP status=%d | pending=%u\n",
                          status, static_cast<unsigned>(reportCount));
            return;
        }
        reportQueue[reportHead] = String();
        reportHead = (reportHead + 1) % kReportQueueCapacity;
        --reportCount;
        Serial.printf("[telemetry] SENT | pending=%u\n", static_cast<unsigned>(reportCount));
    }
}
#else
void initializeReporting() {}
void enqueueSample(const ProbeSample&) {}
void flushReports() {}
#endif

void performProbeAndUpdateStatus() {
    ProbeSample sample;
    const EdgeResult result = runEdgeProbe(&sample);

    if (result == EdgeResult::SSH_ID_PASS) {
        consecutiveEdgeFailures = 0;
        setLedMode(LedMode::HEALTHY);
        Serial.println("[diagnostic] edge=SSH_ID_PASS | led=HEALTHY | no_filtering_verdict");
        enqueueSample(sample);
        flushReports();
        return;
    }

    if (consecutiveEdgeFailures < UINT8_MAX) ++consecutiveEdgeFailures;

    // An Edge failure with a passing independent control is a *suspected*
    // Edge-specific reachability problem, never proof of censorship.
    const bool controlPassed = WiFi.status() == WL_CONNECTED && checkPublicTcpControl(&sample);
    if (controlPassed && consecutiveEdgeFailures >= kPersistentThreshold) {
        setLedMode(LedMode::EDGE_ISSUE);
    } else if (WiFi.status() != WL_CONNECTED) {
        setLedMode(LedMode::WIFI_WAIT);
    } else {
        setLedMode(LedMode::SUSPECT);
    }

    Serial.printf(
        "[diagnostic] edge=%s | control=%s | consecutive_failures=%u | led=%s | no_filtering_verdict\n",
        resultName(result), controlPassed ? "PASS" : "FAIL_OR_UNAVAILABLE",
        static_cast<unsigned>(consecutiveEdgeFailures), ledModeName(ledMode));
    enqueueSample(sample);
    flushReports();
}
} // namespace

void setup() {
    Serial.begin(115200);
    delay(1500);
    Serial.println();
    Serial.println("=== DenaProbe | Edge + LED + Optional HTTPS v0.0.5 ===");
    Serial.printf("Chip: %s | CPU: %u MHz | Flash: %u bytes\n",
                  ESP.getChipModel(), ESP.getCpuFreqMHz(), ESP.getFlashChipSize());

    pinMode(PROBE_LED_PIN, OUTPUT);
    initializeReporting();
    updateLed(millis());
    Serial.printf("[led] mode=WIFI_WAIT | gpio=%u | active_low=%u\n",
                  static_cast<unsigned>(PROBE_LED_PIN),
                  static_cast<unsigned>(PROBE_LED_ACTIVE_LOW));

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
    updateLed(millis());

    if (!validWifiConfig) {
        delay(100);
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
#if DENAPROBE_REPORTING_ENABLED
            configTime(0, 0, "pool.ntp.org", "time.google.com");
#endif
            consecutiveEdgeFailures = 0;
            setLedMode(LedMode::SUSPECT);  // Do not claim healthy before first test.
            probeDue = true;
        } else if (lastStatus == WL_CONNECTED) {
            Serial.println("[wifi] DISCONNECTED");
            consecutiveEdgeFailures = 0;
            setLedMode(LedMode::WIFI_WAIT);
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
        performProbeAndUpdateStatus();
    }

    if (status != WL_CONNECTED && nowMs - lastAttemptMs >= kRetryIntervalMs) {
        Serial.println("[wifi] Retry after 20 seconds without connection");
        WiFi.disconnect();
        beginConnection();
    }

    updateLed(millis());
    delay(50);
}

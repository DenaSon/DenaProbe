// Phase 1B.1: isolated no-credential SSH transport feasibility firmware.
// The default esp32dev environment builds src/main.cpp (v0.0.4) unchanged.
// This firmware never authenticates as a user or tests NPV application traffic.
#include <Arduino.h>
#include <WiFi.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <libssh_esp32.h>
#include <libssh/libssh.h>
#include "wifi_config.h"

#if __has_include("probe_private.h")
#include "probe_private.h"
#else
#define PROBE_EDGE_HOST "CHANGE_ME_EDGE_HOST"
#define PROBE_EDGE_PORT 2252
#endif

#ifndef PROBE_SSH_PIN_SHA256_HEX
#define PROBE_SSH_PIN_SHA256_HEX ""
#endif

namespace {
constexpr uint32_t kRetryWiFiMs = 20000;
constexpr uint32_t kProbeIntervalMs = 60000;
constexpr uint32_t kConnectDeadlineMs = 12000;
constexpr uint32_t kServiceDeadlineMs = 8000;
constexpr uint32_t kTaskStalledMs = 30000;
constexpr uint32_t kWorkerStackBytes = 51200;
constexpr uint32_t kRequiredHeapBeforeTask = 110000;
constexpr uint8_t kLedPin = 2;  // ESP32 DEVKITV1 onboard blue LED, active HIGH

enum class LedMode : uint8_t { WIFI_WAIT, PARTIAL, SSH_READY, SUSPECT };
enum class Code : uint8_t {
    PASS, WIFI_LOST, DNS_FAIL, SESSION_ALLOC_FAILED, SSH_OPTIONS_FAILED,
    SSH_CONNECT_TIMEOUT, SSH_CONNECT_ERROR, HOST_KEY_ERROR, HOST_KEY_MISMATCH,
    SERVICE_ACCEPT_TIMEOUT, SERVICE_REQUEST_ERROR
};

struct Result {
    Code code;
    uint32_t dnsMs;
    uint32_t transportMs;
    uint32_t serviceMs;
    uint32_t freeHeap;
    uint32_t minimumHeap;
    uint32_t largestBlock;
    uint32_t stackWatermark;
};

struct SessionOwner {
    ssh_session session = nullptr;
    ~SessionOwner() { if (session) ssh_free(session); }
};

QueueHandle_t resultQueue = nullptr;
bool validConfig = false;
bool workerRunning = false;
bool stalled = false;
bool probeDue = true;
uint32_t lastWiFiAttemptMs = 0;
uint32_t lastProbeMs = 0;
uint32_t workerStartMs = 0;
LedMode ledMode = LedMode::WIFI_WAIT;
int lastLedLevel = -1;

const char *codeName(Code code) {
    switch (code) {
        case Code::PASS: return "SERVICE_ACCEPT_PASS";
        case Code::WIFI_LOST: return "WIFI_DISCONNECTED";
        case Code::DNS_FAIL: return "DNS_FAIL";
        case Code::SESSION_ALLOC_FAILED: return "RESOURCE_EXHAUSTED";
        case Code::SSH_OPTIONS_FAILED: return "SSH_OPTIONS_ERROR";
        case Code::SSH_CONNECT_TIMEOUT: return "SSH_TRANSPORT_TIMEOUT";
        case Code::SSH_CONNECT_ERROR: return "SSH_TRANSPORT_ERROR";
        case Code::HOST_KEY_ERROR: return "HOST_KEY_UNAVAILABLE";
        case Code::HOST_KEY_MISMATCH: return "HOST_KEY_MISMATCH";
        case Code::SERVICE_ACCEPT_TIMEOUT: return "SERVICE_ACCEPT_TIMEOUT";
        case Code::SERVICE_REQUEST_ERROR: return "SERVICE_REQUEST_ERROR";
    }
    return "UNKNOWN";
}

int hexValue(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

// A pinned SHA256 digest of the server's raw SSH public-key blob, NOT a password.
// Must be provisioned locally from a trusted, independent source (no TOFU).
bool readTrustedPin(uint8_t expected[32]) {
    const char *hex = PROBE_SSH_PIN_SHA256_HEX;
    if (strlen(hex) != 64) return false;
    for (size_t i = 0; i < 32; ++i) {
        const int high = hexValue(hex[2 * i]);
        const int low = hexValue(hex[2 * i + 1]);
        if (high < 0 || low < 0) return false;
        expected[i] = static_cast<uint8_t>((high << 4) | low);
    }
    return true;
}

void updateLed() {
    const uint32_t phase = millis() % 2000U;
    bool on = false;
    switch (ledMode) {
        case LedMode::WIFI_WAIT: on = phase < 1000U; break;
        case LedMode::PARTIAL: on = phase < 1500U; break;
        case LedMode::SSH_READY: on = true; break;
        case LedMode::SUSPECT:
            on = phase < 120U || (phase >= 320U && phase < 440U);
            break;
    }
    const int level = on ? HIGH : LOW;
    if (level != lastLedLevel) {
        digitalWrite(kLedPin, level);
        lastLedLevel = level;
    }
}

Result runSshTransport() {
    Result result{};
    result.code = Code::SSH_CONNECT_ERROR;
    if (WiFi.status() != WL_CONNECTED) {
        result.code = Code::WIFI_LOST;
        return result;
    }

    IPAddress address;
    const uint32_t dnsStart = millis();
    const bool dnsOk = WiFi.hostByName(PROBE_EDGE_HOST, address) == 1;
    result.dnsMs = millis() - dnsStart;
    if (!dnsOk) {
        result.code = Code::DNS_FAIL;
        return result;
    }

    // A new connection is used for the feasibility spike, not the v0.0.4
    // banner socket. Hostname is resolved every run; no Core IP is configured.
    const String resolvedIp = address.toString();
    SessionOwner owner;
    owner.session = ssh_new();
    if (!owner.session) {
        result.code = Code::SESSION_ALLOC_FAILED;
        return result;
    }

    const int servicePort = PROBE_EDGE_PORT;
    const long socketTimeoutSeconds = 10;
    if (ssh_options_set(owner.session, SSH_OPTIONS_HOST, resolvedIp.c_str()) != SSH_OK ||
        ssh_options_set(owner.session, SSH_OPTIONS_PORT, &servicePort) != SSH_OK ||
        ssh_options_set(owner.session, SSH_OPTIONS_TIMEOUT, &socketTimeoutSeconds) != SSH_OK) {
        result.code = Code::SSH_OPTIONS_FAILED;
        return result;
    }

    ssh_set_blocking(owner.session, 0);
    const uint32_t transportStart = millis();
    int rc = SSH_AGAIN;
    while (WiFi.status() == WL_CONNECTED &&
           millis() - transportStart < kConnectDeadlineMs) {
        rc = ssh_connect(owner.session);
        if (rc != SSH_AGAIN) break;
        vTaskDelay(pdMS_TO_TICKS(15));
    }
    result.transportMs = millis() - transportStart;
    if (WiFi.status() != WL_CONNECTED) {
        result.code = Code::WIFI_LOST;
        return result;
    }
    if (rc != SSH_OK) {
        result.code = rc == SSH_AGAIN ? Code::SSH_CONNECT_TIMEOUT
                                     : Code::SSH_CONNECT_ERROR;
        return result;
    }

    // ssh_connect() returned OK: libssh has completed KEX and switched
    // transport keys. Individual KEXINIT/NEWKEYS timings are NOT measured.
    Serial.printf("[ssh-deep] TRANSPORT_PASS | kex_newkeys_combined_ms=%lu\n",
                  static_cast<unsigned long>(result.transportMs));

    ssh_key serverKey = nullptr;
    if (ssh_get_server_publickey(owner.session, &serverKey) != SSH_OK ||
        serverKey == nullptr) {
        result.code = Code::HOST_KEY_ERROR;
        return result;
    }

    unsigned char *digest = nullptr;
    size_t digestLength = 0;
    const int hashRc = ssh_get_publickey_hash(
        serverKey, SSH_PUBLICKEY_HASH_SHA256, &digest, &digestLength);
    ssh_key_free(serverKey);

    uint8_t expected[32] = {};
    const bool trustedPinValid = readTrustedPin(expected);
    bool match = hashRc == SSH_OK && digest != nullptr &&
                 digestLength == 32 && trustedPinValid;
    if (match) {
        uint8_t difference = 0;
        for (size_t i = 0; i < 32; ++i) difference |= digest[i] ^ expected[i];
        match = difference == 0;
    }
    if (digest) ssh_clean_pubkey_hash(&digest);
    memset(expected, 0, sizeof(expected));

    if (!match) {
        result.code = hashRc == SSH_OK ? Code::HOST_KEY_MISMATCH
                                      : Code::HOST_KEY_ERROR;
        return result; // Fail closed BEFORE sending a service request.
    }
    Serial.println("[ssh-deep] HOST_KEY_PASS | trust=PINNED_SHA256");

    // RFC 4253 SSH service request only; NO SSH user authentication attempt.
    const uint32_t serviceStart = millis();
    rc = SSH_AGAIN;
    while (WiFi.status() == WL_CONNECTED &&
           millis() - serviceStart < kServiceDeadlineMs) {
        rc = ssh_service_request(owner.session, "ssh-userauth");
        if (rc != SSH_AGAIN) break;
        vTaskDelay(pdMS_TO_TICKS(15));
    }
    result.serviceMs = millis() - serviceStart;
    if (WiFi.status() != WL_CONNECTED) {
        result.code = Code::WIFI_LOST;
    } else if (rc == SSH_OK) {
        result.code = Code::PASS;
    } else if (rc == SSH_AGAIN) {
        result.code = Code::SERVICE_ACCEPT_TIMEOUT;
    } else {
        result.code = Code::SERVICE_REQUEST_ERROR;
    }
    return result;
}

void sshWorker(void *) {
    Result result = runSshTransport();
    result.freeHeap = ESP.getFreeHeap();
    result.minimumHeap = ESP.getMinFreeHeap();
    result.largestBlock = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    result.stackWatermark = uxTaskGetStackHighWaterMark(nullptr);
    xQueueSend(resultQueue, &result, 0);
    vTaskDelete(nullptr);
}

void printResult(const Result &result) {
    Serial.printf(
        "[ssh-deep] END | result=%s | dns_ms=%lu | transport_ms=%lu | "
        "service_ms=%lu | free_heap=%lu | min_heap=%lu | "
        "largest_block=%lu | stack_watermark_raw=%lu | "
        "auth=NOT_TESTED | npv=NOT_TESTED | filtering_verdict=INCONCLUSIVE\n",
        codeName(result.code),
        static_cast<unsigned long>(result.dnsMs),
        static_cast<unsigned long>(result.transportMs),
        static_cast<unsigned long>(result.serviceMs),
        static_cast<unsigned long>(result.freeHeap),
        static_cast<unsigned long>(result.minimumHeap),
        static_cast<unsigned long>(result.largestBlock),
        static_cast<unsigned long>(result.stackWatermark));
}

void connectWiFi() {
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    lastWiFiAttemptMs = millis();
    Serial.println("[wifi] CONNECTING | hotspot_path=DECLARED");
}
} // namespace

void setup() {
    Serial.begin(115200);
    delay(1500);
    pinMode(kLedPin, OUTPUT);
    updateLed();
    Serial.println("=== DenaProbe | Phase 1B.1 SSH Feasibility (not production) ===");
    Serial.println("[scope] SSH transport + pinned host key + service accept; no auth");

    uint8_t pin[32] = {};
    validConfig =
        strlen(WIFI_SSID) > 0 &&
        strcmp(WIFI_SSID, "CHANGE_ME_HOTSPOT_SSID") != 0 &&
        strlen(PROBE_EDGE_HOST) > 0 &&
        strcmp(PROBE_EDGE_HOST, "CHANGE_ME_EDGE_HOST") != 0 &&
        PROBE_EDGE_PORT > 0 && PROBE_EDGE_PORT <= 65535 &&
        readTrustedPin(pin);
    memset(pin, 0, sizeof(pin));

    if (!validConfig) {
        Serial.println("[ssh-deep] NOT_TESTED | reason=MISSING_CONFIG_OR_PIN");
        Serial.println("[config] Configure a verified SHA256 host-key pin locally.");
        ledMode = LedMode::PARTIAL;
        return;
    }

    resultQueue = xQueueCreate(1, sizeof(Result));
    if (!resultQueue) {
        Serial.println("[ssh-deep] NOT_TESTED | reason=QUEUE_ALLOC_FAILED");
        validConfig = false;
        ledMode = LedMode::SUSPECT;
        return;
    }

    libssh_begin();
    WiFi.mode(WIFI_STA);
    WiFi.setAutoReconnect(false);
    connectWiFi();
}

void loop() {
    updateLed();
    if (!validConfig) {
        delay(50);
        return;
    }

    const uint32_t now = millis();
    Result result{};
    if (resultQueue && xQueueReceive(resultQueue, &result, 0) == pdTRUE) {
        workerRunning = false;
        printResult(result);
        ledMode = (WiFi.status() != WL_CONNECTED) ? LedMode::WIFI_WAIT :
                  result.code == Code::PASS ? LedMode::SSH_READY : LedMode::SUSPECT;
    }

    if (WiFi.status() != WL_CONNECTED) {
        ledMode = LedMode::WIFI_WAIT;
        if (now - lastWiFiAttemptMs >= kRetryWiFiMs) {
            WiFi.disconnect();
            connectWiFi();
        }
    } else if (!workerRunning && !stalled &&
               (probeDue || now - lastProbeMs >= kProbeIntervalMs)) {
        probeDue = false;
        lastProbeMs = now;
        if (ESP.getFreeHeap() < kRequiredHeapBeforeTask) {
            Serial.println("[ssh-deep] NOT_TESTED | reason=LOW_FREE_HEAP");
            ledMode = LedMode::SUSPECT;
        } else {
            ledMode = LedMode::PARTIAL;
            Serial.println("[ssh-deep] START | separate_tcp_session=yes | "
                           "vantage=HOTSPOT_DECLARED | no_filtering_verdict");
            const BaseType_t created = xTaskCreatePinnedToCore(
                sshWorker, "ssh-feas", kWorkerStackBytes, nullptr, 2, nullptr, 1);
            workerRunning = (created == pdPASS);
            workerStartMs = now;
            if (!workerRunning) {
                Serial.println("[ssh-deep] NOT_TESTED | reason=TASK_ALLOC_FAILED");
                ledMode = LedMode::SUSPECT;
            }
        }
    }

    // Never delete an active crypto task. A stalled task blocks further
    // experiments, but the regular LED/Wi-Fi loop remains responsive.
    if (workerRunning && !stalled &&
        millis() - workerStartMs >= kTaskStalledMs) {
        stalled = true;
        ledMode = LedMode::SUSPECT;
        Serial.println("[ssh-deep] UNKNOWN | reason=WORKER_STALLED | "
                       "further_probes=DISABLED");
    }
    delay(20);
}

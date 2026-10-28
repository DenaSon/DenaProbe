// Phase 1B.3-prep: isolated no-credential SSH stage and quality telemetry firmware.
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
#include <libssh/callbacks.h>
#include <libssh/packet.h> // Pinned-port internal API: observe packets, never consume them.
#include <libssh/ssh2.h>
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

// Optional, explicitly validated healthy-path reference. Zero disables
// latency alerts. Do not calibrate against an ongoing incident.
#ifndef PROBE_QUALITY_HEALTHY_TRANSPORT_MS
#define PROBE_QUALITY_HEALTHY_TRANSPORT_MS 0
#endif
#ifndef PROBE_QUALITY_ALERT_RATIO_PERCENT
#define PROBE_QUALITY_ALERT_RATIO_PERCENT 0
#endif

namespace {
constexpr uint32_t kRetryWiFiMs = 20000;
// Incident-capture only: two lightweight SSH handshakes per minute.
constexpr uint32_t kProbeIntervalMs = 30000;
constexpr uint8_t kQualityWindowSamples = 12;
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

// All times are relative to ssh_connect start. -1 means NOT_OBSERVED.
// Receive callbacks observe a packet before libssh validates/processes it.
// Only ssh_connect()==SSH_OK proves the completed KEX/NEWKEYS transport.
struct StageTrace {
    uint32_t startedAt = 0;
    int32_t bannerMs = -1;
    int32_t kexInitTxMs = -1;
    int32_t kexInitRxMs = -1;
    int32_t algorithmsMs = -1;
    int32_t newkeysRxMs = -1;
    bool transportVerified = false;
};

void recordStage(int32_t &destination, const StageTrace &trace) {
    if (destination < 0) {
        destination = static_cast<int32_t>(millis() - trace.startedAt);
    }
}

// libssh-0.11.5 progress: .4 banner, .5 local KEXINIT,
// .6 server KEXINIT, .8 algorithms selected, 1.0 complete transport.
// These callbacks mark *observations* only, not successful verification.
void onConnectProgress(void *userdata, float progress) {
    StageTrace &trace = *static_cast<StageTrace *>(userdata);
    if (progress > 0.39f && progress < 0.41f) {
        recordStage(trace.bannerMs, trace);
    } else if (progress > 0.49f && progress < 0.51f) {
        recordStage(trace.kexInitTxMs, trace);
    } else if (progress > 0.59f && progress < 0.61f) {
        recordStage(trace.kexInitRxMs, trace);
    } else if (progress > 0.79f && progress < 0.81f) {
        recordStage(trace.algorithmsMs, trace);
    }
}

// Observer for incoming SSH_MSG_NEWKEYS, before libssh's own handler.
// MUST return NOT_USED so libssh still enforces packet/state validation.
int observeNewkeys(ssh_session, uint8_t type, ssh_buffer, void *userdata) {
    if (type == SSH2_MSG_NEWKEYS) {
        StageTrace &trace = *static_cast<StageTrace *>(userdata);
        recordStage(trace.newkeysRxMs, trace);
    }
    return SSH_PACKET_NOT_USED;
}

struct Result {
    Code code;
    StageTrace stages;
    uint32_t dnsMs;
    uint32_t transportMs;
    uint32_t serviceMs;
    uint32_t freeHeap;
    uint32_t minimumHeap;
    uint32_t largestBlock;
    uint32_t stackWatermark;
    uint32_t startedAt;
    int16_t wifiRssiDbm; // Phone hotspot Wi-Fi signal; NOT cellular LTE RSSI.
};

struct SessionOwner {
    // Keep all callback storage live through ssh_free() (called in destructor).
    StageTrace stages{};
    ssh_callbacks_struct connectCallbacks{};
    ssh_packet_callback packetHandlers[2]{};
    ssh_packet_callbacks_struct packetCallbacks{};
    ssh_session session = nullptr;

    bool installObservers() {
        stages.startedAt = millis();
        ssh_callbacks_init(&connectCallbacks);
        connectCallbacks.userdata = &stages;
        connectCallbacks.connect_status_function = onConnectProgress;
        if (ssh_set_callbacks(session, &connectCallbacks) != SSH_OK) return false;

        // The observer is installed before ssh_connect registers default
        // handlers. It never consumes/modifies packets or crypto state.
        packetHandlers[0] = nullptr; // Type 20 (KEXINIT) uses progress callback.
        packetHandlers[1] = observeNewkeys; // Type 21 (NEWKEYS).
        packetCallbacks.start = SSH2_MSG_KEXINIT;
        packetCallbacks.n_callbacks = 2;
        packetCallbacks.callbacks = packetHandlers;
        packetCallbacks.user = &stages;
        ssh_packet_set_callbacks(session, &packetCallbacks);
        return true;
    }

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
uint32_t probeSequence = 0;
bool wifiStatusInitialized = false;
bool previousWifiConnected = false;

struct QualitySample {
    Code code;
    uint32_t dnsMs;
    uint32_t transportMs;
    uint32_t serviceMs;
    int16_t wifiRssiDbm;
};
QualitySample qualityHistory[kQualityWindowSamples]{};
uint8_t qualityCount = 0;
uint8_t qualityWriteIndex = 0;

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
    result.startedAt = millis();
    result.wifiRssiDbm = 0; // Not available when the hotspot Wi-Fi is down.
    if (WiFi.status() != WL_CONNECTED) {
        result.code = Code::WIFI_LOST;
        return result;
    }

    result.wifiRssiDbm = static_cast<int16_t>(WiFi.RSSI());
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
    if (!owner.installObservers()) {
        result.code = Code::SSH_OPTIONS_FAILED;
        return result;
    }
    const uint32_t transportStart = owner.stages.startedAt;
    int rc = SSH_AGAIN;
    while (WiFi.status() == WL_CONNECTED &&
           millis() - transportStart < kConnectDeadlineMs) {
        rc = ssh_connect(owner.session);
        if (rc != SSH_AGAIN) break;
        vTaskDelay(pdMS_TO_TICKS(15));
    }
    result.transportMs = millis() - transportStart;
    owner.stages.transportVerified = (rc == SSH_OK);
    result.stages = owner.stages;
    if (WiFi.status() != WL_CONNECTED) {
        result.code = Code::WIFI_LOST;
        return result;
    }
    if (rc != SSH_OK) {
        result.code = rc == SSH_AGAIN ? Code::SSH_CONNECT_TIMEOUT
                                     : Code::SSH_CONNECT_ERROR;
        return result;
    }

    // ssh_connect() success verifies KEX/NEWKEYS jointly. Individual
    // packet observations and negotiations have separate elapsed times.
    // Precise cryptographic KEX vs NEWKEYS processing durations remain UNKNOWN.
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

const char *stopStage(const Result &result) {
    switch (result.code) {
        case Code::WIFI_LOST: return "WIFI";
        case Code::DNS_FAIL: return "DNS";
        case Code::SESSION_ALLOC_FAILED: return "ALLOC";
        case Code::SSH_OPTIONS_FAILED: return "SSH_INIT";
        case Code::HOST_KEY_ERROR:
        case Code::HOST_KEY_MISMATCH: return "HOST_KEY";
        case Code::SERVICE_ACCEPT_TIMEOUT: return "WAIT_SERVICE_ACCEPT";
        case Code::SERVICE_REQUEST_ERROR: return "SERVICE_REQUEST_OR_ACCEPT";
        case Code::PASS: return "SERVICE_ACCEPT_RECEIVED";
        default: break;
    }
    // Do not attribute a transport failure to a specific SSH message
    // until the relevant stage has positive evidence.
    if (result.stages.newkeysRxMs >= 0) return "NEWKEYS_PROCESSING_UNKNOWN";
    if (result.stages.algorithmsMs >= 0) return "KEX_OR_NEWKEYS_UNKNOWN";
    if (result.stages.kexInitRxMs >= 0) return "KEX_NEGOTIATION";
    if (result.stages.kexInitTxMs >= 0) return "WAIT_SERVER_KEXINIT";
    if (result.stages.bannerMs >= 0) return "KEXINIT_SEND_UNKNOWN";
    return "TCP_OR_SSH_BANNER_UNKNOWN";
}

const char *serviceOutcome(Code code) {
    switch (code) {
        case Code::PASS: return "PASS";
        case Code::SERVICE_ACCEPT_TIMEOUT: return "TIMEOUT";
        case Code::SERVICE_REQUEST_ERROR: return "FAIL_OR_UNKNOWN";
        default: return "NOT_TESTED";
    }
}

// This is NOT a throughput test. Per-message differences are elapsed wall
// time, not packet RTT/jitter or crypto processing time.
int32_t elapsedDifference(int32_t endMs, int32_t startMs) {
    return (endMs >= 0 && startMs >= 0 && endMs >= startMs)
               ? endMs - startMs : -1;
}

bool eligibleForAvailability(Code code) {
    switch (code) {
        case Code::PASS:
        case Code::WIFI_LOST:
        case Code::DNS_FAIL:
        case Code::SSH_CONNECT_TIMEOUT:
        case Code::SSH_CONNECT_ERROR:
        case Code::SERVICE_ACCEPT_TIMEOUT:
        case Code::SERVICE_REQUEST_ERROR:
            return true;
        default:
            // Local allocation errors and host-key trust failures are NOT
            // counted as network availability loss.
            return false;
    }
}

void sortLatencies(uint32_t *samples, uint8_t size) {
    for (uint8_t i = 1; i < size; ++i) {
        uint32_t key = samples[i];
        uint8_t j = i;
        while (j > 0 && samples[j - 1] > key) {
            samples[j] = samples[j - 1];
            --j;
        }
        samples[j] = key;
    }
}

// Nearest-rank median/p90. -1 means no successful sample in this window.
int32_t percentile(const uint32_t *sorted, uint8_t size, uint8_t percentage) {
    if (size == 0) return -1;
    const uint8_t rank = static_cast<uint8_t>(
        (static_cast<uint16_t>(size) * percentage + 99U) / 100U);
    return static_cast<int32_t>(sorted[rank - 1]);
}

void printQuality(const Result &result) {
    ++probeSequence;
    const StageTrace &st = result.stages;
    Serial.printf(
        "[quality-sample] seq=%lu | boot_ms=%lu | result=%s | "
        "hotspot_wifi_rssi_dbm=%d | dns_ms=%lu | transport_ms=%lu | "
        "service_ms=%lu | kexinit_exchange_gap_ms=%ld | "
        "kex_to_newkeys_observation_gap_ms=%ld | "
        "newkeys_observation_to_transport_gap_ms=%ld | "
        "throughput=NOT_TESTED | packet_loss=NOT_MEASURED\n",
        static_cast<unsigned long>(probeSequence),
        static_cast<unsigned long>(result.startedAt), codeName(result.code),
        static_cast<int>(result.wifiRssiDbm),
        static_cast<unsigned long>(result.dnsMs),
        static_cast<unsigned long>(result.transportMs),
        static_cast<unsigned long>(result.serviceMs),
        static_cast<long>(elapsedDifference(st.kexInitRxMs, st.kexInitTxMs)),
        static_cast<long>(elapsedDifference(st.newkeysRxMs, st.algorithmsMs)),
        static_cast<long>(st.transportVerified
            ? elapsedDifference(static_cast<int32_t>(result.transportMs), st.newkeysRxMs)
            : -1));

    qualityHistory[qualityWriteIndex] = {
        result.code, result.dnsMs, result.transportMs,
        result.serviceMs, result.wifiRssiDbm
    };
    qualityWriteIndex = (qualityWriteIndex + 1) % kQualityWindowSamples;
    if (qualityCount < kQualityWindowSamples) ++qualityCount;

    uint32_t transport[kQualityWindowSamples]{};
    uint32_t dns[kQualityWindowSamples]{};
    uint32_t service[kQualityWindowSamples]{};
    uint8_t passCount = 0;
    uint8_t validCount = 0;
    uint8_t networkFailures = 0;
    uint8_t wifiFailures = 0;
    uint8_t excludedCount = 0;
    for (uint8_t i = 0; i < qualityCount; ++i) {
        const QualitySample &sample = qualityHistory[i];
        if (!eligibleForAvailability(sample.code)) {
            ++excludedCount;
            continue;
        }
        ++validCount;
        if (sample.code == Code::WIFI_LOST) ++wifiFailures;
        if (sample.code != Code::PASS) {
            ++networkFailures;
            continue;
        }
        transport[passCount] = sample.transportMs;
        dns[passCount] = sample.dnsMs;
        service[passCount] = sample.serviceMs;
        ++passCount;
    }
    sortLatencies(transport, passCount);
    sortLatencies(dns, passCount);
    sortLatencies(service, passCount);

    const int32_t medianTransport = percentile(transport, passCount, 50);
    const int32_t p90Transport = percentile(transport, passCount, 90);
    const int32_t medianDns = percentile(dns, passCount, 50);
    const int32_t medianService = percentile(service, passCount, 50);
    const int32_t transportSpread = passCount > 0
        ? static_cast<int32_t>(transport[passCount - 1] - transport[0]) : -1;

    // Only explicit, externally validated baselines enable slowdown alerts.
    // A bootstrap sample collected DURING a slowdown must never be "healthy".
    const bool referenceConfigured =
        PROBE_QUALITY_HEALTHY_TRANSPORT_MS > 0 &&
        PROBE_QUALITY_ALERT_RATIO_PERCENT >= 100;
    const bool latencySuspect = referenceConfigured && passCount >= 4 &&
        static_cast<uint64_t>(medianTransport) * 100ULL >
        static_cast<uint64_t>(PROBE_QUALITY_HEALTHY_TRANSPORT_MS) *
        static_cast<uint64_t>(PROBE_QUALITY_ALERT_RATIO_PERCENT);
    const char *qualityFlag =
        validCount < 4 ? "COLLECTING" :
        networkFailures >= 2 ? "PATH_FAILURES_OBSERVED" :
        latencySuspect ? "SLOW_HANDSHAKE_SUSPECT" :
        referenceConfigured ? "NO_SSH_LATENCY_ALERT" :
                              "BASELINE_NOT_CALIBRATED";

    Serial.printf(
        "[quality-window] seq=%lu | window=%u/%u | eligible=%u | "
        "pass=%u | network_failures=%u | wifi_lost=%u | excluded=%u | "
        "transport_p50_ms=%ld | transport_p90_ms=%ld | "
        "transport_spread_ms=%ld | dns_p50_ms=%ld | service_p50_ms=%ld | "
        "ssh_latency_flag=%s | download_speed=UNKNOWN | "
        "lte_signal=NOT_MEASURED | filtering_verdict=INCONCLUSIVE\n",
        static_cast<unsigned long>(probeSequence),
        static_cast<unsigned int>(qualityCount),
        static_cast<unsigned int>(kQualityWindowSamples),
        static_cast<unsigned int>(validCount),
        static_cast<unsigned int>(passCount),
        static_cast<unsigned int>(networkFailures),
        static_cast<unsigned int>(wifiFailures),
        static_cast<unsigned int>(excludedCount),
        static_cast<long>(medianTransport),
        static_cast<long>(p90Transport),
        static_cast<long>(transportSpread),
        static_cast<long>(medianDns),
        static_cast<long>(medianService), qualityFlag);
}

void printResult(const Result &result) {
    const StageTrace &stage = result.stages;
    Serial.printf("[ssh-stage] BANNER_RX | state=%s | elapsed_ms=%ld\n",
                  stage.bannerMs >= 0 ? "OBSERVED" : "NOT_OBSERVED",
                  static_cast<long>(stage.bannerMs));
    Serial.printf("[ssh-stage] KEXINIT_TX | state=%s | elapsed_ms=%ld\n",
                  stage.kexInitTxMs >= 0 ? "OBSERVED" : "NOT_OBSERVED",
                  static_cast<long>(stage.kexInitTxMs));
    Serial.printf("[ssh-stage] KEXINIT_RX | state=%s | elapsed_ms=%ld\n",
                  stage.kexInitRxMs >= 0 ? "OBSERVED" : "NOT_OBSERVED",
                  static_cast<long>(stage.kexInitRxMs));
    Serial.printf("[ssh-stage] KEXINIT | outcome=%s\n",
                  stage.algorithmsMs >= 0 ? "PASS" :
                  stage.kexInitRxMs >= 0 ? "UNKNOWN" : "NOT_TESTED");
    Serial.printf("[ssh-stage] KEX_ALGORITHMS | state=%s | elapsed_ms=%ld\n",
                  stage.algorithmsMs >= 0 ? "NEGOTIATED" : "NOT_OBSERVED",
                  static_cast<long>(stage.algorithmsMs));
    Serial.printf("[ssh-stage] NEWKEYS_RX | state=%s | elapsed_ms=%ld\n",
                  stage.newkeysRxMs >= 0 ? "OBSERVED_UNVALIDATED" : "NOT_OBSERVED",
                  static_cast<long>(stage.newkeysRxMs));
    Serial.printf("[ssh-stage] KEX | outcome=%s | crypto_duration_ms=NOT_MEASURED\n",
                  stage.transportVerified ? "PASS" :
                  stage.algorithmsMs >= 0 ? "UNKNOWN" : "NOT_TESTED");
    Serial.printf("[ssh-stage] NEWKEYS | outcome=%s | processing_duration_ms=NOT_MEASURED\n",
                  stage.transportVerified ? "PASS" :
                  stage.newkeysRxMs >= 0 ? "UNKNOWN" : "NOT_TESTED");
    if (result.code == Code::PASS ||
        result.code == Code::SERVICE_ACCEPT_TIMEOUT ||
        result.code == Code::SERVICE_REQUEST_ERROR) {
        Serial.printf("[ssh-stage] SERVICE_ACCEPT | outcome=%s | elapsed_ms=%lu\n",
                      serviceOutcome(result.code),
                      static_cast<unsigned long>(result.serviceMs));
    } else {
        Serial.println("[ssh-stage] SERVICE_ACCEPT | outcome=NOT_TESTED | elapsed_ms=NOT_TESTED");
    }
    Serial.printf("[ssh-deep] stop_stage=%s | no_filtering_verdict\n",
                  stopStage(result));
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
    Serial.println("=== DenaProbe | Phase 1B.3 quality capture (experimental) ===");
    Serial.printf("[quality-config] interval_ms=%lu | window=%u | "
                  "reference_transport_ms=%lu | alert_ratio_percent=%lu | "
                  "baseline_trust=OPERATOR_VALIDATED_ONLY | speed_test=NO\n",
                  static_cast<unsigned long>(kProbeIntervalMs),
                  static_cast<unsigned int>(kQualityWindowSamples),
                  static_cast<unsigned long>(PROBE_QUALITY_HEALTHY_TRANSPORT_MS),
                  static_cast<unsigned long>(PROBE_QUALITY_ALERT_RATIO_PERCENT));
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
    const bool wifiConnected = WiFi.status() == WL_CONNECTED;
    if (!wifiStatusInitialized || wifiConnected != previousWifiConnected) {
        Serial.printf("[quality-link] boot_ms=%lu | wifi=%s | "
                      "signal=HOTSPOT_WIFI_NOT_LTE\n",
                      static_cast<unsigned long>(now),
                      wifiConnected ? "UP" : "DOWN");
        previousWifiConnected = wifiConnected;
        wifiStatusInitialized = true;
    }
    Result result{};
    if (resultQueue && xQueueReceive(resultQueue, &result, 0) == pdTRUE) {
        workerRunning = false;
        printResult(result);
        printQuality(result);
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

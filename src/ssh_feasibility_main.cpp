// DenaProbe R1: isolated ESP32 Wi-Fi SSH feasibility firmware.
// Default src/main.cpp and its PlatformIO build environment are unchanged.
// Separate SSH/HTTPS events share a serialized worker to protect ESP32 heap.
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

#include "denaprobe/ProbeConfig.h"
#include "denaprobe/ProbeTypes.h"
#include "denaprobe/SshProbe.h"
#include "denaprobe/HttpsProbe.h"
#include "denaprobe/ProbeScheduler.h"
#include "denaprobe/ProbeEvents.h"
#include "denaprobe/ProbeState.h"
#include "denaprobe/StatusLed.h"
#include "denaprobe/ProbeQuality.h"
#include "denaprobe/ProbeDiagnostics.h"

namespace {
using namespace DenaProbe;

ProbeEventQueue eventQueue;
ProbeScheduler scheduler;
ProbeState probeState;
StatusLed statusLed;
QualityWindow quality;
bool workerRunning = false;
bool workerRunHttps = false;
uint32_t workerStartMs = 0;
uint32_t lastWiFiAttemptMs = 0;
bool wifiStatusInitialized = false;
bool previousWifiConnected = false;

void connectWiFi() {
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    lastWiFiAttemptMs = millis();
    Serial.println("[wifi] CONNECTING | hotspot_path=DECLARED");
}

void refreshLedState(uint32_t now) {
    statusLed.setMode(probeState.currentState(
        now, WiFi.status() == WL_CONNECTED).led);
}

void probeWorker(void *) {
    // The request is stable for this worker lifetime; the main loop never
    // starts a second worker until it consumes the workerFinished event.
    const bool withHttps = workerRunHttps;
    ProbeEvent sshEvent{};
    sshEvent.kind = ProbeEventKind::SSH_RESULT;
    sshEvent.ssh = runSshTransport();
    sshEvent.ssh.freeHeap = ESP.getFreeHeap();
    sshEvent.ssh.minimumHeap = ESP.getMinFreeHeap();
    sshEvent.ssh.largestBlock =
        heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    sshEvent.ssh.stackWatermark = uxTaskGetStackHighWaterMark(nullptr);
    sshEvent.completedAtMs = millis();
    sshEvent.workerFinished = !withHttps;
    eventQueue.publish(sshEvent); // Publish before HTTPS, even if HTTPS is slow.

    if (withHttps) {
        ProbeEvent httpsEvent{};
        httpsEvent.kind = ProbeEventKind::HTTPS_RESULT;
        httpsEvent.https = runPublicHttpsProbe();
        httpsEvent.completedAtMs = millis();
        httpsEvent.workerFinished = true;
        eventQueue.publish(httpsEvent);
    }
    vTaskDelete(nullptr);
}

void consumeEvent(const ProbeEvent &event) {
    if (event.kind == ProbeEventKind::SSH_RESULT) {
        // SSH completed: the remaining worker work is a separate HTTPS phase.
        // DNS/TCP/TLS budgets from two serial phases must not accumulate into
        // a false worker-stall alarm. A genuine phase stall still latches.
        if (!event.workerFinished) workerStartMs = event.completedAtMs;
        probeState.localProbeError = false;
        probeState.sshLastMeasured = true;
        probeState.lastSshCode = event.ssh.code;
        probeState.lastSshResultAtMs = event.completedAtMs;
        printResult(event.ssh);
        quality.recordAndPrint(event.ssh);
        Serial.printf("[probe-event] type=SSH_RESULT | seq=%lu | "
                      "completed_boot_ms=%lu | worker_finished=%u\n",
                      static_cast<unsigned long>(quality.probeSequence),
                      static_cast<unsigned long>(event.completedAtMs),
                      static_cast<unsigned int>(event.workerFinished));
    } else {
        probeState.httpsLastMeasured = true;
        probeState.lastHttpsStatus = event.https.status;
        probeState.lastHttpsResultAtMs = event.completedAtMs;
        probeState.lastHttpsSampleSeq = quality.probeSequence;
        printHttpsResult(event.https);
        Serial.printf("[probe-event] type=HTTPS_RESULT | ssh_seq=%lu | "
                      "completed_boot_ms=%lu | worker_finished=1\n",
                      static_cast<unsigned long>(quality.probeSequence),
                      static_cast<unsigned long>(event.completedAtMs));
        if (event.https.status == HttpsQuality::Status::CLOCK_NOT_READY) {
            scheduler.retryHttpsNextProbe();
        }
    }

    // The independent SSH result can change the LED before HTTPS completes.
    refreshLedState(millis());
    printOverall(probeState,
                 event.kind == ProbeEventKind::HTTPS_RESULT,
                 WiFi.status() == WL_CONNECTED);
    if (event.workerFinished) workerRunning = false;
}
} // namespace

void setup() {
    Serial.begin(115200);
    delay(1500);
    statusLed.begin();
    statusLed.update();
    Serial.println("=== DenaProbe | R1 separated SSH/HTTPS events (experimental) ===");
    Serial.println("[led-map] solid=SSH_PASS+HTTPS_PASS_OR_DISABLED | "
                   "long_on_short_off=HTTPS_SLOW | triple_flash=HTTPS_ENDPOINT_FAILURE | "
                   "double_flash=SSH_FAILURE | half_second_pulse=UNMEASURED | "
                   "one_second_blink=WIFI_DOWN | vpn_health=NOT_TESTED");
    Serial.printf("[https-config] enabled=%d | interval_ms=%lu | sample_bytes=%lu | "
                  "target=cloudflare_speed_test | ca=GTS_ROOT_R4 | "
                  "tls_verify=REQUIRED | slow_body_threshold_ms=%lu | "
                  "vpn_path=NOT_TESTED\n",
                  PROBE_HTTPS_QUALITY_ENABLED,
                  static_cast<unsigned long>(DenaProbe::kHttpsIntervalMs),
                  static_cast<unsigned long>(HttpsQuality::kBodyBytes),
                  static_cast<unsigned long>(HttpsQuality::kSlowBodyThresholdMs));
    Serial.printf("[quality-config] interval_ms=%lu | window=%u | "
                  "reference_transport_ms=%lu | alert_ratio_percent=%lu | "
                  "baseline_trust=OPERATOR_VALIDATED_ONLY | speed_test=NO\n",
                  static_cast<unsigned long>(DenaProbe::kProbeIntervalMs),
                  static_cast<unsigned int>(DenaProbe::kQualityWindowSamples),
                  static_cast<unsigned long>(PROBE_QUALITY_HEALTHY_TRANSPORT_MS),
                  static_cast<unsigned long>(PROBE_QUALITY_ALERT_RATIO_PERCENT));
    Serial.println("[scope] SSH transport + pinned host key + service accept; no auth");

    uint8_t pin[32] = {};
    probeState.validConfig =
        strlen(WIFI_SSID) > 0 &&
        strcmp(WIFI_SSID, "CHANGE_ME_HOTSPOT_SSID") != 0 &&
        strlen(PROBE_EDGE_HOST) > 0 &&
        strcmp(PROBE_EDGE_HOST, "CHANGE_ME_EDGE_HOST") != 0 &&
        PROBE_EDGE_PORT > 0 && PROBE_EDGE_PORT <= 65535 &&
        DenaProbe::readTrustedPin(pin);
    memset(pin, 0, sizeof(pin));

    if (!probeState.validConfig) {
        Serial.println("[ssh-deep] NOT_TESTED | reason=MISSING_CONFIG_OR_PIN");
        Serial.println("[config] Configure a verified SHA256 host-key pin locally.");
        statusLed.forceUnknown();
        return;
    }
    if (!eventQueue.begin()) {
        Serial.println("[ssh-deep] NOT_TESTED | reason=QUEUE_ALLOC_FAILED");
        probeState.validConfig = false;
        statusLed.forceUnknown();
        return;
    }
    libssh_begin();
    WiFi.mode(WIFI_STA);
    WiFi.setAutoReconnect(false);
    connectWiFi();
    if (PROBE_HTTPS_QUALITY_ENABLED) {
        configTime(0, 0, "time.cloudflare.com", "pool.ntp.org");
    }
}

void loop() {
    statusLed.update();
    if (!probeState.validConfig) {
        delay(50);
        return;
    }
    const uint32_t now = millis();
    const bool wifiConnected = WiFi.status() == WL_CONNECTED;
    if (!wifiStatusInitialized || wifiConnected != previousWifiConnected) {
        if (wifiStatusInitialized && previousWifiConnected && !wifiConnected)
            ++quality.wifiDownTransitions;
        Serial.printf("[quality-link] boot_ms=%lu | wifi=%s | "
                      "signal=HOTSPOT_WIFI_NOT_LTE\n",
                      static_cast<unsigned long>(now),
                      wifiConnected ? "UP" : "DOWN");
        previousWifiConnected = wifiConnected;
        wifiStatusInitialized = true;
    }

    ProbeEvent event{};
    if (eventQueue.receive(event)) consumeEvent(event);

    if (WiFi.status() != WL_CONNECTED) {
        if (now - lastWiFiAttemptMs >= DenaProbe::kRetryWiFiMs) {
            WiFi.disconnect();
            connectWiFi();
        }
    } else if (!workerRunning && !probeState.stalled && scheduler.sshDue(now)) {
        scheduler.markSshStarted(now);
        if (ESP.getFreeHeap() < DenaProbe::kRequiredHeapBeforeTask) {
            Serial.println("[ssh-deep] NOT_TESTED | reason=LOW_FREE_HEAP");
            probeState.localProbeError = true;
        } else {
            workerRunHttps = scheduler.claimHttpsIfDue(
                now, PROBE_HTTPS_QUALITY_ENABLED);
            Serial.println("[ssh-deep] START | separate_tcp_session=yes | "
                           "vantage=HOTSPOT_DECLARED | no_filtering_verdict");
            const BaseType_t created = xTaskCreatePinnedToCore(
                probeWorker, "ssh-feas", DenaProbe::kWorkerStackBytes,
                nullptr, 2, nullptr, 1);
            workerRunning = (created == pdPASS);
            workerStartMs = now;
            if (!workerRunning) {
                Serial.println("[ssh-deep] NOT_TESTED | reason=TASK_ALLOC_FAILED");
                if (workerRunHttps) scheduler.retryHttpsNextProbe();
                probeState.localProbeError = true;
            }
        }
    }

    if (workerRunning && !probeState.stalled &&
        millis() - workerStartMs >= DenaProbe::kTaskStalledMs) {
        probeState.stalled = true;
        Serial.println("[ssh-deep] UNKNOWN | reason=WORKER_STALLED | "
                       "further_probes=DISABLED");
    }
    refreshLedState(millis());
    delay(20);
}


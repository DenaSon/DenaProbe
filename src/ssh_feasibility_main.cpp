// DenaProbe R1: isolated ESP32 Wi-Fi SSH feasibility firmware.
// Default src/main.cpp and its PlatformIO build environment are unchanged.
// Separate SSH/HTTPS events share a serialized worker to protect ESP32 heap.
#include <Arduino.h>
#include <WiFi.h>
#include <time.h>
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
#include "denaprobe/ClockDiagnostics.h"
#include "denaprobe/StatusLed.h"
#include "denaprobe/ProbeQuality.h"
#include "denaprobe/ProbeDiagnostics.h"
#include "denaprobe/TelemetryCodec.h"
#ifndef DENAPROBE_HOST_TEST
#include <esp_system.h>
#if __has_include("telemetry_private.h")
#include "telemetry_private.h"
#endif
#include "denaprobe/TelemetryTransport.h"
#endif

namespace {
using namespace DenaProbe;

ProbeEventQueue eventQueue;
ProbeScheduler scheduler;
ProbeState probeState;
ClockDiagnostics clockDiagnostics;
StatusLed statusLed;
QualityWindow quality;
bool workerRunning = false;
bool workerRunHttps = false;
uint32_t workerStartMs = 0;
uint32_t lastWiFiAttemptMs = 0;
bool wifiStatusInitialized = false;
bool previousWifiConnected = false;

#ifndef DENAPROBE_HOST_TEST
// Telemetry is deliberately optional until a DPT/1 collector exists.
// No sender and no secrets are needed for legacy R1 local operation.
Dpt::Journal telemetryJournal;
Dpt::ExtendedUptime telemetryUptime;
bool telemetryReady = false;
bool telemetryPendingHttps = false;
Result telemetryPendingSsh{};
uint64_t telemetryPendingSshAt = 0;
bool telemetryPendingWifi = false;

QueueHandle_t telemetryCompletionQueue = nullptr;
Dpt::Message telemetryInFlight{};
uint64_t telemetrySendAt = 0;
bool telemetrySending = false;
bool telemetrySenderDisabled = false;
bool telemetryBatchActive = false;
bool telemetryStallLogged = false;
uint32_t telemetryLastBatchMs = 0;
uint32_t telemetryStartedSendMs = 0;
uint32_t telemetryRetryDueMs = 0;
uint8_t telemetryRetries = 0;
uint32_t telemetryLastDropped = 0;

void telemetryWorker(void *) {
    const Dpt::DeliveryResult outcome =
        Dpt::deliver(telemetryInFlight, telemetrySendAt,
                     telemetryJournal.bootId());
    xQueueSend(telemetryCompletionQueue, &outcome, portMAX_DELAY);
    vTaskDelete(nullptr);
}

void telemetryBoot() {
    if (PROBE_DPT_ENABLED && PROBE_DPT_OFFLINE_SMOKE_TEST) {
        Serial.println("[dpt] disabled | reason=ONLINE_AND_SMOKE_MUTUALLY_EXCLUSIVE");
        return;
    }
    if (!PROBE_DPT_ENABLED && !PROBE_DPT_OFFLINE_SMOKE_TEST) {
        Serial.println("[dpt] disabled | collector=NOT_CONFIGURED");
        return;
    }
    if (!PROBE_DPT_OFFLINE_SMOKE_TEST && !Dpt::validSettings()) {
        Serial.println("[dpt] disabled | reason=INVALID_LOCAL_CONFIG");
        return;
    }
    if (!PROBE_DPT_OFFLINE_SMOKE_TEST) {
        telemetryCompletionQueue = xQueueCreate(1, sizeof(Dpt::DeliveryResult));
        if (!telemetryCompletionQueue) {
            Serial.println("[dpt] disabled | reason=QUEUE_ALLOC_FAILED");
            return;
        }
    }
    uint8_t randomBoot[16]{};
    esp_fill_random(randomBoot, sizeof(randomBoot));
    char bootId[33]{};
    constexpr char hex[] = "0123456789abcdef";
    for (uint8_t i = 0; i < sizeof(randomBoot); ++i) {
        bootId[2 * i] = hex[randomBoot[i] >> 4];
        bootId[2 * i + 1] = hex[randomBoot[i] & 0x0f];
    }
    memset(randomBoot, 0, sizeof(randomBoot));
    telemetryUptime.update(millis());
    telemetryReady = telemetryJournal.begin(
        PROBE_DPT_OFFLINE_SMOKE_TEST ? "dp-smoke" : PROBE_DPT_DEVICE_ID,
        bootId,
        static_cast<uint16_t>(PROBE_DPT_OFFLINE_SMOKE_TEST ?
                              1 : PROBE_DPT_TARGET_ID),
        telemetryUptime.now(), WiFi.status() == WL_CONNECTED);
    telemetryLastBatchMs = millis();
    Serial.printf("[dpt] %s | version=1 | mode=%s | queue_capacity=%u | "
                  "period_ms=%lu | one_event_per_post=1 | detection=SERVER_ONLY\n",
                  telemetryReady ? "READY" : "DISABLED",
                  PROBE_DPT_OFFLINE_SMOKE_TEST ? "OFFLINE_SMOKE_NO_NETWORK" : "HTTPS_SENDER",
                  static_cast<unsigned>(Dpt::kQueueCapacity),
                  static_cast<unsigned long>(Dpt::kNormalFlushMs));
}

void telemetryOnSsh(const ProbeEvent &event) {
    if (!telemetryReady) return;
    telemetryPendingHttps = !event.workerFinished;
    telemetryPendingSsh = event.ssh;
    telemetryPendingSshAt = telemetryUptime.at(event.completedAtMs);
    // Capture the link as observed by the SSH probe, not a potentially
    // changed Wi-Fi state at main-loop consumption time.
    telemetryPendingWifi = event.ssh.code != Code::WIFI_LOST &&
                           event.ssh.wifiRssiDbm < 0;
    if (!telemetryPendingHttps) {
        telemetryJournal.pushSsh(telemetryPendingSsh,
                                 telemetryPendingSshAt, telemetryPendingWifi);
    }
}
void telemetryOnHttps(const ProbeEvent &event) {
    if (!telemetryReady || !telemetryPendingHttps) return;
    // A new HTTPS subobject belongs only to the SSH cycle that launched it.
    // The authenticated JSON body is immutable once placed in the journal.
    telemetryJournal.pushSsh(telemetryPendingSsh, telemetryPendingSshAt,
                             telemetryPendingWifi, &event.https,
                             telemetryUptime.at(event.completedAtMs));
    telemetryPendingHttps = false;
}

void telemetryUpdate(uint32_t now, bool probeBusy, bool wifiUp) {
    if (!telemetryReady) return;
    if (PROBE_DPT_OFFLINE_SMOKE_TEST) {
        // Deterministic on-board smoke test: measure and encode real SSH/HTTPS,
        // then display an opaque-ID event WITHOUT contacting any server.
        // Removal here is NOT an ACK and MUST NOT be used as live delivery.
        if (now - telemetryLastBatchMs >= Dpt::kNormalFlushMs) {
            telemetryLastBatchMs = now;
            telemetryBatchActive = true;
        }
        if (!probeBusy) {
            const int index = telemetryJournal.choose();
            const Dpt::Message *sample = index >= 0
                ? telemetryJournal.at(static_cast<uint8_t>(index)) : nullptr;
            if (sample && (sample->urgent || telemetryBatchActive)) {
                Serial.printf("[dpt-smoke] WOULD_SEND_NOT_DELIVERED | "
                              "seq=%lu | kind=%u | length=%u | json=%s\n",
                              static_cast<unsigned long>(sample->sequence),
                              static_cast<unsigned>(sample->kind),
                              static_cast<unsigned>(sample->length), sample->body);
                telemetryJournal.remove(sample->sequence);
            }
        }
        if (telemetryJournal.size() == 0) telemetryBatchActive = false;
        if (telemetryJournal.dropped() != telemetryLastDropped) {
            telemetryLastDropped = telemetryJournal.dropped();
            Serial.printf("[dpt-smoke] dropped_total=%lu | local_test_only=1\n",
                          static_cast<unsigned long>(telemetryLastDropped));
        }
        return;
    }
    if (!telemetryCompletionQueue) return;
    Dpt::DeliveryResult completed{};
    if (xQueueReceive(telemetryCompletionQueue, &completed, 0) == pdTRUE) {
        telemetrySending = false;
        telemetryStallLogged = false;
        const char *outcome = "RETRY";
        switch (completed.kind) {
            case Dpt::Delivery::ACCEPTED: outcome = "ACCEPTED"; break;
            case Dpt::Delivery::DUPLICATE: outcome = "DUPLICATE"; break;
            case Dpt::Delivery::HISTORY_ONLY: outcome = "HISTORY_ONLY"; break;
            case Dpt::Delivery::REJECT: outcome = "REJECTED"; break;
            case Dpt::Delivery::SECURITY: outcome = "SECURITY_PAUSE"; break;
            case Dpt::Delivery::RETRY: break;
        }
        Serial.printf("[dpt-send] seq=%lu | outcome=%s | http=%d | "
                      "queue=%u | detection=SERVER_ONLY\n",
                      static_cast<unsigned long>(completed.sequence), outcome,
                      completed.httpStatus,
                      static_cast<unsigned>(telemetryJournal.size()));
        if (completed.kind == Dpt::Delivery::ACCEPTED ||
            completed.kind == Dpt::Delivery::DUPLICATE ||
            completed.kind == Dpt::Delivery::HISTORY_ONLY) {
            telemetryJournal.remove(completed.sequence);
            telemetryRetries = 0;
            telemetryRetryDueMs = 0;
        } else if (completed.kind == Dpt::Delivery::REJECT) {
            telemetryJournal.discard(completed.sequence);
            telemetryRetries = 0;
            telemetryRetryDueMs = 0;
        } else if (completed.kind == Dpt::Delivery::SECURITY) {
            telemetrySenderDisabled = true;
        } else {
            if (++telemetryRetries >= 6) {
                telemetryJournal.discard(completed.sequence);
                telemetryRetries = 0;
                telemetryRetryDueMs = 0;
                Serial.println("[dpt-send] retry_budget_exhausted | gap=1");
            } else {
                const uint32_t seconds = 5UL << (telemetryRetries - 1);
                const uint32_t delayMs = (seconds > 160UL ? 160UL : seconds)
                    * 1000UL + (esp_random() % 1500UL);
                telemetryRetryDueMs = millis() +
                    (completed.retryAfterMs > delayMs ? completed.retryAfterMs : delayMs);
            }
            telemetryBatchActive = false;
        }
    }
    if (telemetryJournal.size() == 0) telemetryBatchActive = false;
    if (telemetryJournal.dropped() != telemetryLastDropped) {
        telemetryLastDropped = telemetryJournal.dropped();
        Serial.printf("[dpt-queue] dropped_total=%lu | "
                      "historical_gap=1 | flash_storage=NO\n",
                      static_cast<unsigned long>(telemetryLastDropped));
    }
    if (telemetrySending) {
        if (!telemetryStallLogged &&
            now - telemetryStartedSendMs > 30000UL) {
            telemetryStallLogged = true;
            Serial.println("[dpt-send] SENDER_STALLED | no_worker_kill=1");
        }
        return;
    }
    if (telemetrySenderDisabled || !wifiUp || probeBusy ||
        time(nullptr) < 1700000000 || telemetryJournal.size() == 0) return;
    if (telemetryRetryDueMs &&
        static_cast<int32_t>(now - telemetryRetryDueMs) < 0) return;
    if (now - telemetryLastBatchMs >= Dpt::kNormalFlushMs) {
        telemetryLastBatchMs = now;
        telemetryBatchActive = true;
    }
    const int index = telemetryJournal.choose();
    const Dpt::Message *message = telemetryJournal.at(static_cast<uint8_t>(index));
    if (!message || (!message->urgent && !telemetryBatchActive)) return;

    // Copies the record before launching a worker; the journal can then
    // receive new samples without racing the sender's immutable body.
    telemetryInFlight = *message;
    telemetrySendAt = telemetryUptime.now();
    if (telemetrySendAt < telemetryInFlight.completedUptime) return;
    telemetryStartedSendMs = now;
    const BaseType_t created = xTaskCreatePinnedToCore(
        telemetryWorker, "dpt-send", 12288, nullptr, 1, nullptr, 1);
    if (created == pdPASS) telemetrySending = true;
    else Serial.println("[dpt-send] TASK_ALLOC_FAILED | retry_later=1");
}
#endif

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
#ifndef DENAPROBE_HOST_TEST
    if (event.kind == ProbeEventKind::SSH_RESULT)
        telemetryOnSsh(event);
    else telemetryOnHttps(event);
#endif
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
    Serial.println("[led-map] solid=SSH_PASS_UNLESS_HTTPS_SLOW_OR_FAILED | "
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
#ifndef DENAPROBE_HOST_TEST
    telemetryBoot();
#endif
    // Clock diagnostics initialize SNTP later, after WL_CONNECTED + IPv4.
}

void loop() {
    statusLed.update();
    if (!probeState.validConfig) {
        delay(50);
        return;
    }
    const uint32_t now = millis();
#ifndef DENAPROBE_HOST_TEST
    telemetryUptime.update(now);
#endif
    const bool wifiConnected = WiFi.status() == WL_CONNECTED;
    if (!wifiStatusInitialized || wifiConnected != previousWifiConnected) {
        if (wifiStatusInitialized && previousWifiConnected && !wifiConnected)
            ++quality.wifiDownTransitions;
        Serial.printf("[quality-link] boot_ms=%lu | wifi=%s | "
                      "signal=HOTSPOT_WIFI_NOT_LTE\n",
                      static_cast<unsigned long>(now),
                      wifiConnected ? "UP" : "DOWN");
#ifndef DENAPROBE_HOST_TEST
        if (wifiStatusInitialized && telemetryReady)
            telemetryJournal.pushLocal(96, telemetryUptime.now(),
                                       wifiConnected);
#endif
        previousWifiConnected = wifiConnected;
        wifiStatusInitialized = true;
    }

    ProbeEvent event{};
    if (eventQueue.receive(event)) {
#ifndef DENAPROBE_HOST_TEST
        // The worker may finish just after the timestamp captured at the
        // start of this loop. Extend uptime AFTER receiving its event.
        telemetryUptime.update(millis());
#endif
        consumeEvent(event);
    }
#ifndef DENAPROBE_HOST_TEST
    telemetryUpdate(millis(), workerRunning ||
                    scheduler.sshDueWithin(millis(), 18000UL),
                    WiFi.status() == WL_CONNECTED);
#endif

    if (PROBE_HTTPS_QUALITY_ENABLED) {
        const bool up = WiFi.status() == WL_CONNECTED;
        // DHCP must have assigned a usable IPv4 before SNTP setup.
        const bool ipv4Ready = up && WiFi.localIP()[0] != 0;
        clockDiagnostics.update(millis(), up, ipv4Ready,
                                static_cast<int64_t>(time(nullptr)),
                                workerRunning);
    }

    if (WiFi.status() != WL_CONNECTED) {
        if (now - lastWiFiAttemptMs >= DenaProbe::kRetryWiFiMs) {
            WiFi.disconnect();
            connectWiFi();
        }
    } else if (!workerRunning && !probeState.stalled
#ifndef DENAPROBE_HOST_TEST
               && !telemetrySending
#endif
               && scheduler.sshDue(now)) {
        scheduler.markSshStarted(now);
        if (ESP.getFreeHeap() < DenaProbe::kRequiredHeapBeforeTask) {
            Serial.println("[ssh-deep] NOT_TESTED | reason=LOW_FREE_HEAP");
            probeState.localProbeError = true;
#ifndef DENAPROBE_HOST_TEST
            if (telemetryReady) telemetryJournal.pushLocal(
                90, telemetryUptime.now(), true);
#endif
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
#ifndef DENAPROBE_HOST_TEST
                if (telemetryReady) telemetryJournal.pushLocal(
                    95, telemetryUptime.now(), true);
#endif
            }
        }
    }

    if (workerRunning && !probeState.stalled &&
        millis() - workerStartMs >= DenaProbe::kTaskStalledMs) {
        probeState.stalled = true;
#ifndef DENAPROBE_HOST_TEST
        if (telemetryReady) telemetryJournal.pushLocal(
            92, telemetryUptime.now(), WiFi.status() == WL_CONNECTED);
#endif
        Serial.println("[ssh-deep] UNKNOWN | reason=WORKER_STALLED | "
                       "further_probes=DISABLED");
    }
    refreshLedState(millis());
    delay(20);
}


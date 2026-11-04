#pragma once
// Experimental, opt-in R3 authenticated SSH data-plane witness.
// This is NOT a customer NPV client, filtering verdict or administrative shell.
// Caller MUST verify the pinned SSH host key before calling this function.
#include <Arduino.h>
#include <WiFi.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <libssh/libssh.h>
#include "ProbeTypes.h"

#ifndef PROBE_DEEP_ENABLED
#define PROBE_DEEP_ENABLED 0
#endif
#ifndef PROBE_DEEP_USER
#define PROBE_DEEP_USER ""
#endif
// 0 keeps the existing R3 key-auth experiment; 1 opts into password auth.
// Passwords are provisioned only in ignored local configuration, never CI.
#ifndef PROBE_DEEP_AUTH_MODE
#define PROBE_DEEP_AUTH_MODE 0
#endif
#ifndef PROBE_DEEP_PASSWORD
#define PROBE_DEEP_PASSWORD ""
#endif
#ifndef PROBE_DEEP_PRIVATE_KEY_B64
#define PROBE_DEEP_PRIVATE_KEY_B64 ""
#endif
// Safe A2 default: authenticate only; no SSH forwarding to unapproved targets.
// Must be explicitly set to 0 AFTER destination and permit review.
#ifndef PROBE_DEEP_AUTH_ONLY
#define PROBE_DEEP_AUTH_ONLY 1
#endif
#ifndef PROBE_DEEP_REMOTE_HOST
#define PROBE_DEEP_REMOTE_HOST "127.0.0.1"
#endif
#ifndef PROBE_DEEP_REMOTE_PORT
#define PROBE_DEEP_REMOTE_PORT 18180
#endif
#ifndef PROBE_DEEP_SAMPLE_BYTES
#define PROBE_DEEP_SAMPLE_BYTES 16384UL
#endif
#ifndef PROBE_DEEP_DWELL_MS
#define PROBE_DEEP_DWELL_MS 20000UL
#endif
#ifndef PROBE_DEEP_EVERY_N_CYCLES
#define PROBE_DEEP_EVERY_N_CYCLES 2
#endif
#ifndef PROBE_LITE_SAMPLE_BYTES
#define PROBE_LITE_SAMPLE_BYTES 8192UL
#endif
#ifndef PROBE_LITE_DWELL_MS
#define PROBE_LITE_DWELL_MS 5000UL
#endif
#ifndef PROBE_LITE_EVERY_N_CYCLES
#define PROBE_LITE_EVERY_N_CYCLES 1
#endif

namespace DenaProbe {
#if PROBE_DEEP_ENABLED
inline bool authSettingsValid() {
    const size_t userLen = strlen(PROBE_DEEP_USER);
#if PROBE_DEEP_AUTH_MODE == 1
    const size_t secretLen = strlen(PROBE_DEEP_PASSWORD);
    const bool credentialsValid = secretLen >= 1 && secretLen <= 128;
#elif PROBE_DEEP_AUTH_MODE == 0
    const bool credentialsValid = strlen(PROBE_DEEP_PRIVATE_KEY_B64) > 50;
#else
    const bool credentialsValid = false; // Never silently select an auth fallback.
#endif
    return PROBE_DEEP_ENABLED && userLen >= 1 && userLen <= 48 &&
           credentialsValid &&
           PROBE_DEEP_EVERY_N_CYCLES >= 1 && PROBE_DEEP_EVERY_N_CYCLES <= 30;
}

inline bool deepSettingsValid() {
    if (!authSettingsValid()) return false;
#if defined(PROBE_B3_LITE) && PROBE_B3_LITE
    if (PROBE_LITE_SAMPLE_BYTES < 1024UL ||
        PROBE_LITE_SAMPLE_BYTES > 16384UL ||
        PROBE_LITE_DWELL_MS > 10000UL ||
        PROBE_LITE_EVERY_N_CYCLES < 1 ||
        PROBE_LITE_EVERY_N_CYCLES > 30) return false;
    // Require a hostname with an alphabetic public DNS suffix; reject literal
    // loopback/private IPs and the unused placeholder. Public routability
    // still needs a separate operator-approved Core-side preflight.
    const char *target = PROBE_DEEP_REMOTE_HOST;
    const size_t n = strlen(target);
    if (n < 4 || n > 128 ||
        strcmp(target, "CHANGE_ME_LITE_HOST") == 0 ||
        strcmp(target, "localhost") == 0) return false;
    bool hasLetter = false, hasDot = false;
    for (size_t i = 0; i < n; ++i) {
        const char x = target[i];
        const bool letter = (x >= 'a' && x <= 'z') ||
                            (x >= 'A' && x <= 'Z');
        hasLetter |= letter;
        hasDot |= x == '.';
        if (!(letter || (x >= '0' && x <= '9') ||
              x == '-' || x == '.')) return false;
    }
    if (!hasLetter || !hasDot ||
        (n >= 6 && strcmp(target + n - 6, ".local") == 0)) return false;
#else
    if (strcmp(PROBE_DEEP_REMOTE_HOST, "127.0.0.1") != 0) return false;
#endif
    return
           PROBE_DEEP_REMOTE_PORT >= 1 && PROBE_DEEP_REMOTE_PORT <= 65535 &&
           PROBE_DEEP_SAMPLE_BYTES >= 1 && PROBE_DEEP_SAMPLE_BYTES <= 65536UL &&
           PROBE_DEEP_DWELL_MS <= 30000UL;
}

// A controlled relay-local TCP responder sends exactly N bytes of the byte 0x5A
// on each fresh forwarded connection, then closes. No user traffic is inspected.
inline TransferEvidence deepTransfer(ssh_session session) {
    TransferEvidence out{};
    out.attempted = true;
#if defined(PROBE_B3_LITE) && PROBE_B3_LITE
    out.requested = PROBE_LITE_SAMPLE_BYTES;
#else
    out.requested = PROBE_DEEP_SAMPLE_BYTES;
#endif
    out.code = 23; // channel error until opened
    const uint32_t start = millis();
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) { out.elapsedMs = millis() - start; return out; }
    int rc = SSH_AGAIN;
    while (WiFi.status() == WL_CONNECTED && millis() - start < 5000UL) {
        rc = ssh_channel_open_forward(channel, PROBE_DEEP_REMOTE_HOST,
                                      PROBE_DEEP_REMOTE_PORT, "127.0.0.1", 0);
        if (rc != SSH_AGAIN) break;
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    if (rc != SSH_OK) {
        out.code = WiFi.status() != WL_CONNECTED ? 90 :
            (rc == SSH_AGAIN ? 20 : 23);
        out.elapsedMs = millis() - start;
        ssh_channel_free(channel);
        return out;
    }
    out.channelOpened = true;
    out.code = 20;  // timeout until complete
    const uint32_t bodyStart = millis();
    uint8_t chunk[512]{};
    bool wrongBody = false;
    while (WiFi.status() == WL_CONNECTED &&
           millis() - bodyStart < 12000UL && out.received < out.requested) {
        const uint32_t remaining = out.requested - out.received;
        const int want = static_cast<int>(
            remaining < sizeof(chunk) ? remaining : sizeof(chunk));
        rc = ssh_channel_read_timeout(channel, chunk, want, 0, 100);
        if (rc > 0) {
            for (int i = 0; i < rc; ++i)
                if (chunk[i] != 0x5A) wrongBody = true;
            out.received += static_cast<uint32_t>(rc);
        } else if (rc == SSH_ERROR) {
            out.code = 21;
            break;
        } else if (rc == 0 && ssh_channel_is_eof(channel)) {
            out.code = 22;
            break;
        } else {
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }
    out.elapsedMs = millis() - start;
    if (out.received == out.requested && !wrongBody) out.code = 1;
    else if (wrongBody) out.code = 21; // integrity fail, not "complete"
    else if (WiFi.status() != WL_CONNECTED) out.code = 90;
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return out;
}

// Wire-compatible auth results: 1 success; 10 rejected/partial;
// 11 deadline; 12 protocol/library error; 90 local/unmeasurable.
// None is an SSH filtering verdict or an excuse to retry bad credentials.
struct DeepAuthAttempt {
    uint16_t code = 90;
    uint32_t elapsedMs = 0;
};

inline DeepAuthAttempt performDeepAuth(ssh_session session) {
    DeepAuthAttempt out{};
    const uint32_t started = millis();
    int rc = SSH_AUTH_AGAIN;
#if PROBE_DEEP_AUTH_MODE == 1
    // A verified pinned host key is a mandatory caller precondition.
    // The session remains non-blocking; AGAIN never extends the wall deadline.
    while (WiFi.status() == WL_CONNECTED && millis() - started < 8000UL) {
        rc = ssh_userauth_password(session, PROBE_DEEP_USER, PROBE_DEEP_PASSWORD);
        if (rc != SSH_AUTH_AGAIN) break;
        vTaskDelay(pdMS_TO_TICKS(20));
    }
#elif PROBE_DEEP_AUTH_MODE == 0
    ssh_key key = nullptr;
    if (ssh_pki_import_privkey_base64(PROBE_DEEP_PRIVATE_KEY_B64, nullptr,
                                      nullptr, nullptr, &key) != SSH_OK || !key) {
        out.elapsedMs = millis() - started;
        return out;
    }
    while (WiFi.status() == WL_CONNECTED && millis() - started < 8000UL) {
        rc = ssh_userauth_publickey(session, nullptr, key);
        if (rc != SSH_AUTH_AGAIN) break;
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    ssh_key_free(key);
#endif
    out.elapsedMs = millis() - started;
    if (WiFi.status() != WL_CONNECTED) out.code = 90;
    else if (rc == SSH_AUTH_AGAIN) out.code = 11;
    else if (rc == SSH_AUTH_DENIED || rc == SSH_AUTH_PARTIAL) out.code = 10;
    else if (rc == SSH_AUTH_SUCCESS) out.code = 1;
    else out.code = 12;
    return out;
}

inline const char *deepAuthOutcome(uint16_t code) {
    switch (code) {
        case 1: return "AUTH_SUCCESS";
        case 10: return "AUTH_REJECTED";
        case 11: return "AUTH_TIMEOUT";
        case 12: return "AUTH_ERROR";
        default: return "LOCAL_UNMEASURABLE";
    }
}

// B3: authenticate on the pinned SSH session; no channel is allocated.
inline void runEdgeAuthOnly(ssh_session session, AuthEvidence &out) {
    out.measured = true;
    const DeepAuthAttempt attempt = performDeepAuth(session);
    out.code = attempt.code;
    out.elapsedMs = attempt.elapsedMs;
    out.completedAtMs = millis();
    Serial.printf("[edge-auth] mode=PASSWORD | outcome=%s | ms=%lu | "
                  "host_key=PIN_VERIFIED | forwarding=NOT_TESTED | "
                  "filtering_verdict=INCONCLUSIVE\n",
                  deepAuthOutcome(out.code),
                  static_cast<unsigned long>(out.elapsedMs));
}

inline void printDeepTransfer(const char *stage, const TransferEvidence &e) {
    Serial.printf("[deep] %s | attempted=%u | channel_open=%u | "
                  "bytes=%lu/%lu | ms=%lu | code=%u\n",
                  stage, static_cast<unsigned>(e.attempted),
                  static_cast<unsigned>(e.channelOpened),
                  static_cast<unsigned long>(e.received),
                  static_cast<unsigned long>(e.requested),
                  static_cast<unsigned long>(e.elapsedMs),
                  static_cast<unsigned>(e.code));
}

inline void runAuthenticatedDeep(ssh_session session, DeepEvidence &out,
                                 AuthEvidence *authOut = nullptr) {
    out.measured = true;
    out.code = 90;
    // deepSettingsValid() restricts this witness to 127.0.0.1:18180.
    // Label even auth/channel failures as attempted Core-loopback evidence.
#if defined(PROBE_B3_LITE) && PROBE_B3_LITE
    out.routeKind = 2;  // Controlled public SSH-forward destination, NOT NPV proof.
#else
    out.routeKind = PROBE_DEEP_AUTH_ONLY ? 0 : 1;
#endif
    const uint32_t started = millis();
    const DeepAuthAttempt auth = performDeepAuth(session);
    out.authCode = auth.code;
    out.authMs = auth.elapsedMs;
    if (authOut) {
        authOut->measured = true;
        authOut->code = auth.code;
        authOut->elapsedMs = auth.elapsedMs;
        authOut->completedAtMs = millis(); // Before channel/dwell measurements.
    }
    Serial.printf("[deep] AUTH | mode=%s | outcome=%s | ms=%lu | "
                  "host_key=PIN_VERIFIED_BY_CALLER\n",
                  PROBE_DEEP_AUTH_MODE == 1 ? "PASSWORD" : "PUBLIC_KEY",
                  deepAuthOutcome(out.authCode),
                  static_cast<unsigned long>(out.authMs));

    if (out.authCode != 1) {
        out.code = out.authCode;
    } else if (PROBE_DEEP_AUTH_ONLY) {
        // A2 first physical pilot: prove credentials without a channel open.
        // Code 90 means DATA-PLANE NOT TESTED, never Deep SUCCESS (code 1).
        out.code = 90;
        Serial.println("[deep] CHANNEL | outcome=NOT_TESTED | reason=AUTH_ONLY");
        Serial.println("[deep] TRANSFER_1 | outcome=NOT_TESTED");
        Serial.println("[deep] TRANSFER_2 | outcome=NOT_TESTED");
    } else {
        // The same authenticated session is used for both independent
        // allowlisted forwarding channels with a controlled dwell in between.
        out.first = deepTransfer(session);
        printDeepTransfer("TRANSFER_1", out.first);
        if (out.first.code == 1) {
            const uint32_t dwell = millis();
            while (WiFi.status() == WL_CONNECTED &&
                   millis() - dwell <
#if defined(PROBE_B3_LITE) && PROBE_B3_LITE
                       PROBE_LITE_DWELL_MS &&
#else
                       PROBE_DEEP_DWELL_MS &&
#endif
                   ssh_is_connected(session)) {
                vTaskDelay(pdMS_TO_TICKS(50));
            }
            Serial.printf("[deep] DWELL | ms=%lu | session_connected=%u\n",
                          static_cast<unsigned long>(millis() - dwell),
                          static_cast<unsigned>(ssh_is_connected(session)));
            if (WiFi.status() == WL_CONNECTED && ssh_is_connected(session)) {
                out.second = deepTransfer(session);
                printDeepTransfer("TRANSFER_2", out.second);
            } else {
                Serial.println("[deep] TRANSFER_2 | outcome=NOT_TESTED");
            }
            if (!ssh_is_connected(session)) {
                out.code = 20;  // session closed/reset unexpectedly
            } else if (!out.second.attempted) {
                out.code = 21;  // no valid second sample
            } else if (!out.second.channelOpened) {
                out.code = out.second.code == 20 ? 31 : 30;
            } else if (out.second.code == 1) {
                out.code = 1;
            } else if (out.second.code == 20) {
                out.code = 40;
            } else {
                out.code = 41;
            }
        } else if (!ssh_is_connected(session)) {
            out.code = 20;
        } else if (!out.first.channelOpened) {
            out.code = out.first.code == 20 ? 31 : 30;
        } else if (out.first.code == 20) {
            out.code = 40;
        } else {
            out.code = 41;
        }
    }
    // Local hotspot loss takes precedence over all remote stage hypotheses.
    if (WiFi.status() != WL_CONNECTED) out.code = 90;
    out.sessionMs = millis() - started;
    out.completedAtMs = millis();
    Serial.printf("[deep] SUMMARY | auth=%s | deep_code=%u | session_ms=%lu | "
                  "free_heap=%lu | min_heap=%lu | largest_block=%lu | "
                  "stack_watermark_raw=%lu | filtering_verdict=INCONCLUSIVE\n",
                  deepAuthOutcome(out.authCode), static_cast<unsigned>(out.code),
                  static_cast<unsigned long>(out.sessionMs),
                  static_cast<unsigned long>(ESP.getFreeHeap()),
                  static_cast<unsigned long>(ESP.getMinFreeHeap()),
                  static_cast<unsigned long>(
                      heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)),
                  static_cast<unsigned long>(uxTaskGetStackHighWaterMark(nullptr)));
}
#else
inline bool deepSettingsValid() { return false; }
inline void runAuthenticatedDeep(ssh_session, DeepEvidence &) {}
#endif
} // namespace DenaProbe

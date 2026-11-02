#pragma once
// Experimental, opt-in R3 authenticated SSH data-plane witness.
// This is NOT a customer NPV client, filtering verdict or administrative shell.
// Caller MUST verify the pinned SSH host key before calling this function.
#include <Arduino.h>
#include <WiFi.h>
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
#ifndef PROBE_DEEP_PRIVATE_KEY_B64
#define PROBE_DEEP_PRIVATE_KEY_B64 ""
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

namespace DenaProbe {
inline bool deepSettingsValid() {
    return PROBE_DEEP_ENABLED && strlen(PROBE_DEEP_USER) >= 1 &&
           strlen(PROBE_DEEP_USER) <= 48 &&
           strlen(PROBE_DEEP_PRIVATE_KEY_B64) > 50 &&
           strcmp(PROBE_DEEP_REMOTE_HOST, "127.0.0.1") == 0 &&
           PROBE_DEEP_REMOTE_PORT >= 1 && PROBE_DEEP_REMOTE_PORT <= 65535 &&
           PROBE_DEEP_SAMPLE_BYTES >= 1 && PROBE_DEEP_SAMPLE_BYTES <= 65536UL &&
           PROBE_DEEP_DWELL_MS <= 30000UL &&
           PROBE_DEEP_EVERY_N_CYCLES >= 1 && PROBE_DEEP_EVERY_N_CYCLES <= 30;
}

// A controlled relay-local TCP responder sends exactly N bytes of the byte 0x5A
// on each fresh forwarded connection, then closes. No user traffic is inspected.
inline TransferEvidence deepTransfer(ssh_session session) {
    TransferEvidence out{};
    out.attempted = true;
    out.requested = PROBE_DEEP_SAMPLE_BYTES;
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
        out.code = rc == SSH_AGAIN ? 20 : 23;
        out.elapsedMs = millis() - start;
        ssh_channel_free(channel);
        return out;
    }
    out.code = 20;  // timeout until complete
    const uint32_t bodyStart = millis();
    uint8_t chunk[512]{};
    bool wrongBody = false;
    while (WiFi.status() == WL_CONNECTED &&
           millis() - bodyStart < 12000UL && out.received < out.requested) {
        const int want = static_cast<int>(
            min(static_cast<uint32_t>(sizeof(chunk)), out.requested - out.received));
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

inline void runAuthenticatedDeep(ssh_session session, DeepEvidence &out) {
    out.measured = true;
    out.code = 90;
    const uint32_t started = millis();
    ssh_key key = nullptr;
    // Private key is a dedicated, provisioned, ignored *local* secret; no
    // user credentials or unprotected fallback are ever used.
    if (ssh_pki_import_privkey_base64(PROBE_DEEP_PRIVATE_KEY_B64, nullptr,
                                       nullptr, nullptr, &key) != SSH_OK || !key) {
        out.completedAtMs = millis();
        return;
    }
    int rc = SSH_AUTH_AGAIN;
    const uint32_t authStart = millis();
    while (WiFi.status() == WL_CONNECTED && millis() - authStart < 8000UL) {
        rc = ssh_userauth_publickey(session, nullptr, key);
        if (rc != SSH_AUTH_AGAIN) break;
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    ssh_key_free(key);
    out.authMs = millis() - authStart;
    if (WiFi.status() != WL_CONNECTED) {
        out.code = 90;
    } else if (rc == SSH_AUTH_AGAIN) {
        out.code = 11;
    } else if (rc == SSH_AUTH_DENIED || rc == SSH_AUTH_PARTIAL) {
        out.code = 10;
    } else if (rc != SSH_AUTH_SUCCESS) {
        out.code = 12;
    } else {
        // This is the *same authenticated session* for both independent
        // forwarding channel attempts, separated by the controlled dwell.
        out.first = deepTransfer(session);
        if (out.first.code == 1) {
            const uint32_t dwell = millis();
            while (WiFi.status() == WL_CONNECTED &&
                   millis() - dwell < PROBE_DEEP_DWELL_MS &&
                   ssh_is_connected(session)) {
                vTaskDelay(pdMS_TO_TICKS(50));
            }
            if (WiFi.status() == WL_CONNECTED && ssh_is_connected(session)) {
                out.second = deepTransfer(session);
            }
            if (!ssh_is_connected(session)) {
                out.code = 20;  // session closed/reset unexpectedly
            } else if (!out.second.attempted) {
                out.code = 21;  // session timed out before second sample
            } else if (out.second.code == 1) {
                out.code = 1;   // both full, deterministic bodies verified
            } else if (out.second.code == 20) {
                out.code = 40;  // data timeout
            } else {
                out.code = 41;  // incomplete/channel failure
            }
        } else if (!ssh_is_connected(session)) {
            out.code = 20;
        } else if (out.first.code == 20) {
            out.code = 40;
        } else {
            out.code = 41;
        }
    }
    out.sessionMs = millis() - started;
    out.completedAtMs = millis();
}
} // namespace DenaProbe

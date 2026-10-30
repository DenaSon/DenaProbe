#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <libssh_esp32.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/packet.h>
#include <libssh/ssh2.h>
#include "ProbeConfig.h"
#include "ProbeTypes.h"

// No authentication, SSH channel or NPV data-path operation in R1.
// libssh progress callbacks are observational and MUST NOT consume packets.
namespace DenaProbe {
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
    // A resolver failure while the hotspot disappears is a local link loss.
    // Recheck even on a cached DNS success before opening an SSH session.
    if (WiFi.status() != WL_CONNECTED) {
        result.code = Code::WIFI_LOST;
        return result;
    }
    if (!dnsOk) {
        // When the Edge hostname cannot be resolved, run an independent,
        // limited DNS-only control on the SAME hotspot resolver.
        // No SSH connection is attempted. The result is not a censorship
        // or general-internet verdict; some hosts may resolve selectively.
        const IPAddress primaryDns = WiFi.dnsIP(0);
        const IPAddress secondaryDns = WiFi.dnsIP(1);
        const IPAddress gateway = WiFi.gatewayIP();
        IPAddress controlAddress;
        const uint32_t controlStart = millis();
        const bool controlOk =
            WiFi.hostByName("example.com", controlAddress) == 1;
        const uint32_t controlMs = millis() - controlStart;
        if (WiFi.status() != WL_CONNECTED) {
            result.code = Code::WIFI_LOST;
            return result;
        }
        const String dns1 = primaryDns.toString();
        const String dns2 = secondaryDns.toString();
        const String gw = gateway.toString();
        Serial.printf(
            "[dns-diag] edge_resolve=FAIL | independent_control=example.com | "
            "control_resolve=%s | control_ms=%lu | primary_dns=%s | "
            "secondary_dns=%s | gateway=%s | "
            "cause=UNCONFIRMED | dns_control_not_internet_speed_test\n",
            controlOk ? "PASS" : "FAIL",
            static_cast<unsigned long>(controlMs),
            dns1.c_str(), dns2.c_str(), gw.c_str());
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

} // namespace DenaProbe


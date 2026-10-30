#pragma once
#include <Arduino.h>
#include "../https_quality.h"
// DenaProbe R1 internal module: compiled only by the experimental PlatformIO entrypoint.

namespace DenaProbe {
enum class LedMode : uint8_t {
    WIFI_DOWN, UNKNOWN, SSH_READY, HTTPS_SLOW, HTTPS_FAILURE, SSH_FAILURE
};
enum class SshPathState : uint8_t {
    NOT_TESTED, PASS, FAILURE, LOCAL_UNMEASURABLE, STALE
};
enum class PublicHttpsState : uint8_t {
    CHECK_DISABLED, NOT_TESTED, PASS, SLOW_SUSPECT, ENDPOINT_FAILURE, UNMEASURABLE, STALE
};
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

struct CurrentState {
    SshPathState ssh;
    PublicHttpsState https;
    LedMode led;
};

} // namespace DenaProbe

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

// DPT/2: all fields are observations, never filtering decisions.
struct TcpEvidence {
    bool measured = false;
    uint16_t code = 90;        // LOCAL_UNMEASURABLE until a socket was attempted
    uint32_t elapsedMs = 0;
    uint32_t completedAtMs = 0;
};
struct TransferEvidence {
    bool attempted = false;
    bool channelOpened = false; // local aggregation only; not a wire value
    uint16_t code = 90;
    uint32_t requested = 0;
    uint32_t received = 0;
    uint32_t elapsedMs = 0;
};
// B3: independent observation of an Edge SSH login (no forwarding).
struct AuthEvidence {
    bool measured = false;
    uint16_t code = 90; // 1=success, 10=rejected, 11=timeout, 12=error, 90=local
    uint32_t elapsedMs = 0;
    uint32_t completedAtMs = 0;
};
struct DeepEvidence {
    bool measured = false;
    uint16_t code = 90;        // deep-session status
    uint32_t completedAtMs = 0;
    uint16_t authCode = 90;   // Local-only stage result; not a DPT/2 wire field.
    // Signed z.rt=1 is Core-loopback; 2 is historical static responder;
    // 3 is bounded public HTTP over authenticated SSH forwarding. None proves full NPV.
    // 0 = no route claim / legacy, omitted from wire.
    uint8_t routeKind = 0;
    uint32_t authMs = 0;
    uint32_t sessionMs = 0;
    TransferEvidence first{};
    TransferEvidence second{};
};

struct Result {
    // IPv4 resolved from the public Edge hostname in this same probe cycle.
    // Empty for DNS failure/Wi-Fi loss; never reused across probes.
    char resolvedEdgeIp[16]{};
    TcpEvidence tcp{};
    DeepEvidence deep{};
    AuthEvidence auth{}; // Auth measured independently from Core-loopback.
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

// B1 first physical pilot deliberately excludes Deep evidence from production
// DPT/2 while preserving independent TCP/SSH/HTTPS telemetry. The Core's
// existing detector can interpret loopback channel failure as D1 and full
// loopback samples as HEALTHY, neither of which proves NPV internet egress.
// A separately reviewed Core classification/target-isolation gate is required
// before a later signed Deep field trial. Serial keeps full Deep diagnostics.
inline Result telemetrySafeResult(const Result &result) {
    Result safe = result;
#if defined(PROBE_B1_FORWARDING_PILOT) && PROBE_B1_FORWARDING_PILOT
    safe.deep = DeepEvidence{};
#endif
// Existing Core rejects route=2. Retain signed preauth/TCP until Core Phase 2.
#if defined(PROBE_B3_LITE) && PROBE_B3_LITE
#if !defined(PROBE_B3_LITE_WIRE) || !PROBE_B3_LITE_WIRE
    safe.deep = DeepEvidence{};
#endif
#endif
    return safe;
}

struct CurrentState {
    SshPathState ssh;
    PublicHttpsState https;
    LedMode led;
};

} // namespace DenaProbe

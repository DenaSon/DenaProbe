#pragma once
#include "ProbeTypes.h"
#include "ProbeConfig.h"

namespace DenaProbe {
// State of the last actual measurement for each independent channel.
// Rolling historic failures never overwrite the latest sampled result.
class ProbeState {
public:
    bool validConfig = false;
    bool stalled = false;
    bool localProbeError = false;
    bool sshLastMeasured = false;
    bool deepLastMeasured = false;
    uint16_t lastDeepCode = 90;
    uint32_t deepLastResultAtMs = 0;
    bool httpsLastMeasured = false;
    Code lastSshCode = Code::SSH_CONNECT_ERROR;
    uint32_t lastSshResultAtMs = 0;
    uint32_t lastHttpsResultAtMs = 0;
    uint32_t lastHttpsSampleSeq = 0;
    HttpsQuality::Status lastHttpsStatus = HttpsQuality::Status::NOT_TESTED;

CurrentState currentState(uint32_t now, bool wifiConnected) const {
    CurrentState state{
        SshPathState::NOT_TESTED, PublicHttpsState::NOT_TESTED, LedMode::UNKNOWN
    };
    if (!PROBE_HTTPS_QUALITY_ENABLED) {
        state.https = PublicHttpsState::CHECK_DISABLED;
    } else if (!httpsLastMeasured) {
        state.https = PublicHttpsState::NOT_TESTED;
    } else if (now - lastHttpsResultAtMs >= kHttpsFreshnessMs) {
        state.https = PublicHttpsState::STALE;
    } else {
        switch (lastHttpsStatus) {
            case HttpsQuality::Status::PASS:
                state.https = PublicHttpsState::PASS;
                break;
            case HttpsQuality::Status::SLOW_64K_SAMPLE_SUSPECT:
                state.https = PublicHttpsState::SLOW_SUSPECT;
                break;
            case HttpsQuality::Status::CLOCK_NOT_READY:
            case HttpsQuality::Status::LOW_MEMORY:
            case HttpsQuality::Status::WIFI_DOWN:
            case HttpsQuality::Status::NOT_TESTED:
                state.https = PublicHttpsState::UNMEASURABLE;
                break;
            default:
                // DNS, TLS, HTTP and short-body errors are limited to the
                // tested endpoint, not proof of global internet or filtering.
                state.https = PublicHttpsState::ENDPOINT_FAILURE;
                break;
        }
    }

    if (!validConfig || stalled || localProbeError) {
        state.ssh = SshPathState::LOCAL_UNMEASURABLE;
    } else if (!sshLastMeasured) {
        state.ssh = SshPathState::NOT_TESTED;
    } else if (now - lastSshResultAtMs >= kSshFreshnessMs) {
        state.ssh = SshPathState::STALE;
    } else {
        switch (lastSshCode) {
            case Code::PASS:
                state.ssh = SshPathState::PASS;
                break;
            case Code::SESSION_ALLOC_FAILED:
            case Code::SSH_OPTIONS_FAILED:
            case Code::WIFI_LOST:
                state.ssh = SshPathState::LOCAL_UNMEASURABLE;
                break;
            default:
                // Includes DNS/transport/service failures and host-key errors.
                // Raw result indicates precise stage/reason; no censor verdict.
                state.ssh = SshPathState::FAILURE;
                break;
        }
    }

    // Deep is a future experiment. The production monitoring-only build
    // carries no runtime dependency on Deep evidence or credentials.
#if PROBE_DEEP_ENABLED
    // Preserve the experimental LED safety behavior when explicitly built.
    const bool deepMissing =
        !deepLastMeasured || now - deepLastResultAtMs > 3U * kProbeIntervalMs;
    const bool deepLocal = deepLastMeasured &&
        (lastDeepCode == 90 || lastDeepCode == 10 ||
         lastDeepCode == 11 || lastDeepCode == 12);
    const bool deepFailure = deepLastMeasured &&
        lastDeepCode != 1 && !deepLocal && !deepMissing;
#else
    constexpr bool deepMissing = false;
    constexpr bool deepLocal = false;
    constexpr bool deepFailure = false;
#endif
    if (!wifiConnected) {
        state.led = LedMode::WIFI_DOWN;
    } else if (state.ssh == SshPathState::FAILURE || deepFailure) {
        state.led = LedMode::SSH_FAILURE;
    } else if (state.ssh != SshPathState::PASS ||
               deepMissing || deepLocal) {
        state.led = LedMode::UNKNOWN;
    } else if (state.https == PublicHttpsState::SLOW_SUSPECT) {
        state.led = LedMode::HTTPS_SLOW;
    } else if (state.https == PublicHttpsState::ENDPOINT_FAILURE) {
        state.led = LedMode::HTTPS_FAILURE;
    } else {
        // A fresh SSH SERVICE_ACCEPT_PASS is the primary LED health signal.
        // Missing, stale or unmeasurable HTTPS (including NTP not ready)
        // is not evidence of an SSH failure.
        state.led = LedMode::SSH_READY;
    }
    return state;
}

};
} // namespace DenaProbe

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

    if (!wifiConnected) {
        state.led = LedMode::WIFI_DOWN;
    } else if (state.ssh == SshPathState::FAILURE) {
        state.led = LedMode::SSH_FAILURE;
    } else if (state.ssh != SshPathState::PASS) {
        state.led = LedMode::UNKNOWN;
    } else if (state.https == PublicHttpsState::SLOW_SUSPECT) {
        state.led = LedMode::HTTPS_SLOW;
    } else if (state.https == PublicHttpsState::ENDPOINT_FAILURE) {
        state.led = LedMode::HTTPS_FAILURE;
    } else if (state.https == PublicHttpsState::PASS ||
               state.https == PublicHttpsState::CHECK_DISABLED) {
        state.led = LedMode::SSH_READY;
    } else {
        state.led = LedMode::UNKNOWN;
    }
    return state;
}

};
} // namespace DenaProbe

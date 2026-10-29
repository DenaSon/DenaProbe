#pragma once
#include <Arduino.h>
#include "ProbeTypes.h"
#include "ProbeState.h"
#include "StatusLed.h"
#include "ProbeQuality.h"
#include "ProbeConfig.h"

namespace DenaProbe {
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

const char *sshPathName(SshPathState state) {
    switch (state) {
        case SshPathState::NOT_TESTED: return "NOT_TESTED";
        case SshPathState::PASS: return "SERVICE_ACCEPT_PASS";
        case SshPathState::FAILURE: return "PATH_FAILURE";
        case SshPathState::LOCAL_UNMEASURABLE: return "LOCAL_UNMEASURABLE";
        case SshPathState::STALE: return "STALE";
    }
    return "UNKNOWN";
}

const char *publicHttpsName(PublicHttpsState state) {
    switch (state) {
        case PublicHttpsState::CHECK_DISABLED: return "DISABLED";
        case PublicHttpsState::NOT_TESTED: return "NOT_TESTED";
        case PublicHttpsState::PASS: return "PASS";
        case PublicHttpsState::SLOW_SUSPECT: return "SLOW_SAMPLE_SUSPECT";
        case PublicHttpsState::ENDPOINT_FAILURE: return "ENDPOINT_FAILURE";
        case PublicHttpsState::UNMEASURABLE: return "UNMEASURABLE";
        case PublicHttpsState::STALE: return "STALE";
    }
    return "UNKNOWN";
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

void printHttpsResult(const HttpsQuality::Result &h) {
    Serial.printf(
        "[https-quality] target=cloudflare_speed_test | path=DIRECT_HOTSPOT_NOT_VPN | "
        "result=%s | bytes=%lu/%lu | dns_ms=%lu | headers_ms=%lu | "
        "first_body_ms=%lu | body_transfer_ms=%lu | total_ms=%lu | "
        "body_rate_kibps_approx=%lu | http_code=%d | stream_code=%d | "
        "tls_cert_check=ENABLED | vpn_data_path=NOT_TESTED | "
        "telegram_update=NOT_TESTED | general_internet_verdict=INCONCLUSIVE\n",
        HttpsQuality::statusName(h.status),
        static_cast<unsigned long>(h.bytes),
        static_cast<unsigned long>(HttpsQuality::kBodyBytes),
        static_cast<unsigned long>(h.dnsMs),
        static_cast<unsigned long>(h.headersMs),
        static_cast<unsigned long>(h.firstBodyMs),
        static_cast<unsigned long>(h.bodyTransferMs),
        static_cast<unsigned long>(h.totalMs),
        static_cast<unsigned long>(h.approxKibPerSec),
        h.httpCode, h.httpStreamResult);
}

void printOverall(const ProbeState &snapshot, uint32_t sshSequence, bool httpsNewSample, bool wifiConnected) {
    const uint32_t now = millis();
    const CurrentState state = snapshot.currentState(now, wifiConnected);
    const uint32_t ageMs = snapshot.httpsLastMeasured ? now - snapshot.lastHttpsResultAtMs : 0;
    const bool httpsFresh = snapshot.httpsLastMeasured && ageMs < kHttpsFreshnessMs;

    // Preserve the existing tagged output, but add independent machine-readable
    // states, observation age and provenance (new vs cached HTTPS sample).
    const char *overall =
        !wifiConnected ? "WIFI_DOWN" :
        state.ssh == SshPathState::FAILURE ? "SSH_NOT_READY" :
        state.ssh != SshPathState::PASS ? "SSH_UNMEASURABLE_OR_STALE" :
        state.https == PublicHttpsState::CHECK_DISABLED ? "SSH_PASS_HTTPS_DISABLED" :
        state.https == PublicHttpsState::PASS
            ? "SSH_PASS_PUBLIC_HTTPS_PASS_VPN_UNKNOWN" :
        state.https == PublicHttpsState::SLOW_SUSPECT
            ? "SSH_PASS_PUBLIC_HTTPS_SLOW_SUSPECT" :
        state.https == PublicHttpsState::ENDPOINT_FAILURE
            ? "SSH_PASS_PUBLIC_HTTPS_ENDPOINT_FAILURE" :
              "SSH_PASS_HTTPS_UNMEASURABLE_OR_STALE";
    Serial.printf(
        "[probe-overall] ssh=%s | ssh_path=%s | https=%s | "
        "public_https=%s | https_new_sample=%u | https_sample_seq=%lu | "
        "https_sample_age_ms=%ld | https_fresh=%u | status=%s | led=%s | "
        "vpn=NOT_TESTED | filtering_verdict=INCONCLUSIVE\n",
        codeName(snapshot.lastSshCode), sshPathName(state.ssh),
        httpsFresh ? HttpsQuality::statusName(snapshot.lastHttpsStatus) : "NOT_TESTED",
        publicHttpsName(state.https),
        static_cast<unsigned int>(httpsNewSample ? 1 : 0),
        static_cast<unsigned long>(snapshot.lastHttpsSampleSeq),
        snapshot.httpsLastMeasured ? static_cast<long>(ageMs) : -1L,
        static_cast<unsigned int>(httpsFresh ? 1 : 0),
        overall, ledName(state.led));
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

} // namespace DenaProbe

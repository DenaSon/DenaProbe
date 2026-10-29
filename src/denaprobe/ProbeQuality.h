#pragma once
#include <Arduino.h>
#include "ProbeTypes.h"
#include "ProbeConfig.h"

namespace DenaProbe {
const char *codeName(Code code); // Implemented in ProbeDiagnostics.h.
int32_t elapsedDifference(int32_t endMs, int32_t startMs); // Signed stage delta or NOT_MEASURED.
bool eligibleForAvailability(Code code) {
    switch (code) {
        case Code::PASS:
        case Code::WIFI_LOST:
        case Code::DNS_FAIL:
        case Code::SSH_CONNECT_TIMEOUT:
        case Code::SSH_CONNECT_ERROR:
        case Code::SERVICE_ACCEPT_TIMEOUT:
        case Code::SERVICE_REQUEST_ERROR:
            return true;
        default:
            // Local allocation errors and host-key trust failures are NOT
            // counted as network availability loss.
            return false;
    }
}

void sortLatencies(uint32_t *samples, uint8_t size) {
    for (uint8_t i = 1; i < size; ++i) {
        uint32_t key = samples[i];
        uint8_t j = i;
        while (j > 0 && samples[j - 1] > key) {
            samples[j] = samples[j - 1];
            --j;
        }
        samples[j] = key;
    }
}

// Nearest-rank median/p90. -1 means no successful sample in this window.
int32_t percentile(const uint32_t *sorted, uint8_t size, uint8_t percentage) {
    if (size == 0) return -1;
    const uint8_t rank = static_cast<uint8_t>(
        (static_cast<uint16_t>(size) * percentage + 99U) / 100U);
    return static_cast<int32_t>(sorted[rank - 1]);
}

class QualityWindow {
public:
    uint32_t probeSequence = 0;
    uint32_t wifiDownTransitions = 0;
struct QualitySample {
    Code code;
    uint32_t dnsMs;
    uint32_t transportMs;
    uint32_t serviceMs;
    int16_t wifiRssiDbm;
};
    QualitySample qualityHistory[kQualityWindowSamples]{};
    uint8_t qualityCount = 0;
    uint8_t qualityWriteIndex = 0;

void recordAndPrint(const Result &result) {
    ++probeSequence;
    const StageTrace &st = result.stages;
    Serial.printf(
        "[quality-sample] seq=%lu | boot_ms=%lu | result=%s | "
        "hotspot_wifi_rssi_dbm=%d | dns_ms=%lu | transport_ms=%lu | "
        "service_ms=%lu | kexinit_exchange_gap_ms=%ld | "
        "kex_to_newkeys_observation_gap_ms=%ld | "
        "newkeys_observation_to_transport_gap_ms=%ld | "
        "throughput=NOT_TESTED | packet_loss=NOT_MEASURED\n",
        static_cast<unsigned long>(probeSequence),
        static_cast<unsigned long>(result.startedAt), codeName(result.code),
        static_cast<int>(result.wifiRssiDbm),
        static_cast<unsigned long>(result.dnsMs),
        static_cast<unsigned long>(result.transportMs),
        static_cast<unsigned long>(result.serviceMs),
        static_cast<long>(elapsedDifference(st.kexInitRxMs, st.kexInitTxMs)),
        static_cast<long>(elapsedDifference(st.newkeysRxMs, st.algorithmsMs)),
        static_cast<long>(st.transportVerified
            ? elapsedDifference(static_cast<int32_t>(result.transportMs), st.newkeysRxMs)
            : -1));

    qualityHistory[qualityWriteIndex] = {
        result.code, result.dnsMs, result.transportMs,
        result.serviceMs, result.wifiRssiDbm
    };
    qualityWriteIndex = (qualityWriteIndex + 1) % kQualityWindowSamples;
    if (qualityCount < kQualityWindowSamples) ++qualityCount;

    uint32_t transport[kQualityWindowSamples]{};
    uint32_t dns[kQualityWindowSamples]{};
    uint32_t service[kQualityWindowSamples]{};
    uint8_t passCount = 0;
    uint8_t validCount = 0;
    uint8_t networkFailures = 0;
    uint8_t wifiFailures = 0;
    uint8_t excludedCount = 0;
    for (uint8_t i = 0; i < qualityCount; ++i) {
        const QualitySample &sample = qualityHistory[i];
        if (!eligibleForAvailability(sample.code)) {
            ++excludedCount;
            continue;
        }
        ++validCount;
        if (sample.code == Code::WIFI_LOST) ++wifiFailures;
        if (sample.code != Code::PASS) {
            ++networkFailures;
            continue;
        }
        transport[passCount] = sample.transportMs;
        dns[passCount] = sample.dnsMs;
        service[passCount] = sample.serviceMs;
        ++passCount;
    }
    sortLatencies(transport, passCount);
    sortLatencies(dns, passCount);
    sortLatencies(service, passCount);

    const int32_t medianTransport = percentile(transport, passCount, 50);
    const int32_t p90Transport = percentile(transport, passCount, 90);
    const int32_t medianDns = percentile(dns, passCount, 50);
    const int32_t medianService = percentile(service, passCount, 50);
    const int32_t transportSpread = passCount > 0
        ? static_cast<int32_t>(transport[passCount - 1] - transport[0]) : -1;

    // Only explicit, externally validated baselines enable slowdown alerts.
    // A bootstrap sample collected DURING a slowdown must never be "healthy".
    const bool referenceConfigured =
        PROBE_QUALITY_HEALTHY_TRANSPORT_MS > 0 &&
        PROBE_QUALITY_ALERT_RATIO_PERCENT >= 100;
    const bool latencySuspect = referenceConfigured && passCount >= 4 &&
        static_cast<uint64_t>(medianTransport) * 100ULL >
        static_cast<uint64_t>(PROBE_QUALITY_HEALTHY_TRANSPORT_MS) *
        static_cast<uint64_t>(PROBE_QUALITY_ALERT_RATIO_PERCENT);
    const char *qualityFlag =
        validCount < 4 ? "COLLECTING" :
        networkFailures >= 2 ? "PATH_FAILURES_OBSERVED" :
        latencySuspect ? "SLOW_HANDSHAKE_SUSPECT" :
        referenceConfigured ? "NO_SSH_LATENCY_ALERT" :
                              "BASELINE_NOT_CALIBRATED";

    Serial.printf(
        "[quality-window] seq=%lu | window=%u/%u | eligible=%u | "
        "pass=%u | network_failures=%u | wifi_lost=%u | "
        "wifi_down_events_since_boot=%lu | excluded=%u | "
        "transport_p50_ms=%ld | transport_p90_ms=%ld | "
        "transport_spread_ms=%ld | dns_p50_ms=%ld | service_p50_ms=%ld | "
        "ssh_latency_flag=%s | download_speed=UNKNOWN | "
        "lte_signal=NOT_MEASURED | filtering_verdict=INCONCLUSIVE\n",
        static_cast<unsigned long>(probeSequence),
        static_cast<unsigned int>(qualityCount),
        static_cast<unsigned int>(kQualityWindowSamples),
        static_cast<unsigned int>(validCount),
        static_cast<unsigned int>(passCount),
        static_cast<unsigned int>(networkFailures),
        static_cast<unsigned int>(wifiFailures),
        static_cast<unsigned long>(wifiDownTransitions),
        static_cast<unsigned int>(excludedCount),
        static_cast<long>(medianTransport),
        static_cast<long>(p90Transport),
        static_cast<long>(transportSpread),
        static_cast<long>(medianDns),
        static_cast<long>(medianService), qualityFlag);
}

};
} // namespace DenaProbe

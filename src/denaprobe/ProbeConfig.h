#pragma once
#include <Arduino.h>

// Runtime intervals and deadlines are intentionally preserved for R1.
#ifndef PROBE_HTTPS_QUALITY_ENABLED
#define PROBE_HTTPS_QUALITY_ENABLED 1
#endif
#ifndef PROBE_QUALITY_HEALTHY_TRANSPORT_MS
#define PROBE_QUALITY_HEALTHY_TRANSPORT_MS 0
#endif
#ifndef PROBE_QUALITY_ALERT_RATIO_PERCENT
#define PROBE_QUALITY_ALERT_RATIO_PERCENT 0
#endif
namespace DenaProbe {
constexpr uint32_t kRetryWiFiMs = 20000;
// Incident-capture only: two lightweight SSH handshakes per minute.
constexpr uint32_t kProbeIntervalMs = 30000;
constexpr uint8_t kQualityWindowSamples = 12;
constexpr uint32_t kHttpsIntervalMs = 180000U; // 64 KiB every 3min ≈ 30MiB/day.
// The current SSH status becomes UNKNOWN if no successful worker completion is
// observed for three regular probe intervals; old window failures are historical.
constexpr uint32_t kSshFreshnessMs = 3U * kProbeIntervalMs;
constexpr uint32_t kHttpsFreshnessMs = 2U * kHttpsIntervalMs;
constexpr uint32_t kConnectDeadlineMs = 12000;
constexpr uint32_t kServiceDeadlineMs = 8000;
constexpr uint32_t kTaskStalledMs = 55000; // Sequential SSH then HTTPS, separate result events.
constexpr uint32_t kWorkerStackBytes = 51200;
constexpr uint32_t kRequiredHeapBeforeTask = 110000;
constexpr uint8_t kLedPin = 2;  // ESP32 DEVKITV1 onboard blue LED, active HIGH

} // namespace DenaProbe

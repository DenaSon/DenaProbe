#pragma once
#include <Arduino.h>
#include "ProbeConfig.h"

namespace DenaProbe {
// Start-to-start cadence. No overlapping workers. Wrap-safe modulo uint32_t.
// Keep existing 30s SSH and 180s HTTPS timing through R1.
class ProbeScheduler {
public:
    bool sshDue(uint32_t now) const {
        return firstSshDue_ || now - lastSshStartMs_ >= kProbeIntervalMs;
    }
    void markSshStarted(uint32_t now) {
        firstSshDue_ = false;
        lastSshStartMs_ = now;
    }
    bool claimHttpsIfDue(uint32_t now, bool enabled) {
        if (!enabled || (!httpsRetryDue_ && now - lastHttpsStartMs_ < kHttpsIntervalMs)) return false;
        httpsRetryDue_ = false;
        lastHttpsStartMs_ = now;
        return true;
    }
    void retryHttpsNextProbe() { httpsRetryDue_ = true; }
private:
    bool firstSshDue_ = true;
    uint32_t lastSshStartMs_ = 0;
    bool httpsRetryDue_ = true;
    uint32_t lastHttpsStartMs_ = 0;
};
} // namespace DenaProbe

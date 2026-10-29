#pragma once
#include <Arduino.h>
#include "ProbeTypes.h"
#include "ProbeConfig.h"

namespace DenaProbe {
const char *ledName(LedMode mode) {
    switch (mode) {
        case LedMode::WIFI_DOWN: return "WIFI_DOWN";
        case LedMode::UNKNOWN: return "UNKNOWN";
        case LedMode::SSH_READY: return "SSH_READY";
        case LedMode::HTTPS_SLOW: return "PUBLIC_HTTPS_SLOW";
        case LedMode::HTTPS_FAILURE: return "PUBLIC_HTTPS_FAILURE";
        case LedMode::SSH_FAILURE: return "SSH_FAILURE";
    }
    return "UNKNOWN";
}


class StatusLed {
public:
    void begin() { pinMode(kLedPin, OUTPUT); }
    LedMode mode() const { return ledMode; }
    void forceUnknown() { ledMode = LedMode::UNKNOWN; }
void update() {
    const uint32_t phase = millis() % 2000U;
    bool on = false;
    switch (ledMode) {
        case LedMode::WIFI_DOWN:     // 1s on, 1s off
            on = phase < 1000U;
            break;
        case LedMode::UNKNOWN:       // 0.5s on, 1.5s off
            on = phase < 500U;
            break;
        case LedMode::SSH_READY:     // Solid = tested SSH reachable; NOT VPN
            on = true;
            break;
        case LedMode::HTTPS_SLOW:    // 1.5s on, 0.5s off: warning only
            on = phase < 1500U;
            break;
        case LedMode::HTTPS_FAILURE: // Triple short flashes
            on = phase < 120U ||
                 (phase >= 300U && phase < 420U) ||
                 (phase >= 600U && phase < 720U);
            break;
        case LedMode::SSH_FAILURE:   // Two short flashes
            on = phase < 120U || (phase >= 320U && phase < 440U);
            break;
    }
    const int level = on ? HIGH : LOW;
    if (level != lastLedLevel) {
        digitalWrite(kLedPin, level);
        lastLedLevel = level;
    }
}

void setMode(LedMode next) {
    if (next != ledMode) {
        ledMode = next;
        Serial.printf("[led-state] mode=%s | vpn_path=NOT_TESTED | "
                      "meaning=TESTED_PATHS_ONLY\n", ledName(ledMode));
    }
}

private:
    LedMode ledMode = LedMode::WIFI_DOWN;
    int lastLedLevel = -1;
};
} // namespace DenaProbe

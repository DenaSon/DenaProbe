#include <Arduino.h>

// Phase 0: USB/serial hardware smoke test only.
// No Wi-Fi, modem, network measurements, or external endpoints.
void setup() {
    Serial.begin(115200);
    delay(1500);

    Serial.println();
    Serial.println("=== DenaProbe | Hardware Smoke Test v0.0.1 ===");
    Serial.printf("Chip: %s\n", ESP.getChipModel());
    Serial.printf("CPU: %u MHz\n", ESP.getCpuFreqMHz());
    Serial.printf("Flash: %u bytes\n", ESP.getFlashChipSize());
    Serial.printf("Free heap: %u bytes\n", ESP.getFreeHeap());
    Serial.println("Status: READY");
}

void loop() {
    static uint32_t lastPrintMs = 0;
    const uint32_t nowMs = millis();

    if (nowMs - lastPrintMs >= 2000) {
        lastPrintMs = nowMs;
        Serial.printf("[uptime=%lu s] OK\n", static_cast<unsigned long>(nowMs / 1000));
    }
}

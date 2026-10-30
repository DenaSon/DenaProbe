#pragma once
#include "Arduino.h"
constexpr int WL_CONNECTED = 3, WIFI_STA = 1;
struct IPAddress {
    String toString() const { return "192.0.2.1"; }
    uint8_t operator[](int index) const {
        return Fake::ipReady ? static_cast<uint8_t>(index == 0 ? 192 : 1) : 0;
    }
};
struct WiFiStub {
    int status() const { return Fake::wifi ? WL_CONNECTED : 0; }
    int RSSI() const { return -50; }
    int hostByName(const char *, IPAddress &) {
        Fake::tick(10);
        ++Fake::dnsCalls;
        if (Fake::dnsCalls == Fake::dropOnDns) Fake::wifi = false;
        return Fake::dnsCalls == 1 ? Fake::edgeDns : Fake::controlDns;
    }
    IPAddress localIP() { return {}; }
    IPAddress dnsIP(int) { return {}; }
    IPAddress gatewayIP() { return {}; }
    void begin(const char *, const char *) {}
    void disconnect() { Fake::wifi = false; }
    void mode(int) {}
    void setAutoReconnect(bool) {}
};
inline WiFiStub WiFi;
inline void configTime(long, int, const char *, const char *) {
    ++Fake::sntpConfigCalls;
}

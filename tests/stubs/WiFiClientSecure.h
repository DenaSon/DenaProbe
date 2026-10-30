#pragma once
#include "WiFi.h"
class WiFiClientSecure : public Stream {
public:
    virtual int connect(const char *, uint16_t, int32_t) { assert(false); return 0; }
    virtual int connect(const char *h, uint16_t p) { return connect(h, p, 7000); }
    int connect(IPAddress, uint16_t port, const char *host, const char *ca,
                const char *, const char *) {
        assert(port == 443 && host && ca);
        ++Fake::connects; Fake::tlsHostname = host; Fake::tlsRoot = ca;
        Fake::tick(100); open_ = Fake::tlsConnect; return open_;
    }
    virtual uint8_t connected() { Fake::tick(); return open_; }
    int available() override { Fake::tick(); return 0; }
    int read() override {
        Fake::tick(100);
        return Fake::response == Fake::Response::DRIP_HEADERS ? 'x' : -1;
    }
    virtual int read(uint8_t *, size_t) { Fake::tick(); return -1; }
    int peek() override { return read(); }
    void flush() override {}
    size_t write(uint8_t) override { return 1; }
    size_t write(const uint8_t *, size_t n) override { return n; }
    void stop() { if (open_) ++Fake::stops; open_ = false; }
    void setCACert(const char *) {}
    void setHandshakeTimeout(unsigned long) {}
    void setConnectionTimeout(uint32_t) {}
private:
    bool open_ = false;
};

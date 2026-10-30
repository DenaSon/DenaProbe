#pragma once
#include "WiFiClientSecure.h"
constexpr int HTTP_CODE_OK = 200;
// Scripted server / HTTP adapter, not a replacement TLS or HTTP parser test.
// Exercises the pinned HTTPClient's source access patterns: polling connected
// without sink writes, zero-byte reads, and per-character chunk/header reads.
class HTTPClient {
public:
    void setConnectTimeout(int) {}
    void setTimeout(uint32_t ms) { timeout_ = ms; }
    void setReuse(bool) {}
    bool begin(WiFiClientSecure &client, const char *) { client_ = &client; return true; }
    void addHeader(const char *, const char *) {}
    int GET() {
        client_->setTimeout(timeout_);
        if (!client_->connect("speed.cloudflare.com", 443, 7000)) return -1;
        if (Fake::response == Fake::Response::SILENT_HEADERS ||
            Fake::response == Fake::Response::DRIP_HEADERS) {
            // Deliberately keep responding without ending the header line.
            while (client_->connected()) client_->readStringUntil('\n');
            return -1;
        }
        return Fake::httpCode;
    }
    int getSize() { return Fake::contentLength; }
    int writeToStream(Stream *sink) {
        if (Fake::response == Fake::Response::SILENT_CHUNK_HEADER) {
            while (client_->connected()) client_->readStringUntil('\n');
            return -1;
        }
        if (Fake::response == Fake::Response::SILENT_BODY) {
            uint8_t byte = 0;
            while (client_->connected()) {
                if (Fake::contentLength < 0) client_->available();
                else {
                    client_->read(&byte, 1);
                    sink->write(&byte, 0);
                }
            }
            return -1;
        }
        int total = 0;
        uint8_t data[1024]{};
        while (client_->connected() && total < Fake::payloadSize) {
            const bool drip = Fake::response == Fake::Response::DRIP_BODY;
            Fake::tick(drip ? 1000 : Fake::bodyDelay);
            // HTTPClient reads from the guarded source before writing a chunk.
            if (!client_->connected()) return -1;
            const size_t n = std::min(drip ? 1 : 1024, Fake::payloadSize - total);
            if (sink->write(data, n) != n) return -1;
            total += n;
        }
        return total;
    }
    void end() { client_->stop(); }
private:
    WiFiClientSecure *client_ = nullptr;
    uint32_t timeout_ = 4000;
};

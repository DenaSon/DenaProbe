// Experimental small HTTPS data-path sample, independent from SSH and VPN.
// No credentials, redirects, uploads, persistent payloads, or setInsecure().
#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <esp_heap_caps.h>
#include <time.h>

namespace HttpsQuality {

constexpr uint32_t kBodyBytes = 65536U;
constexpr uint32_t kMaxBodyMs = 12000U;
constexpr uint32_t kMinFreeHeap = 95000U;
constexpr uint32_t kMinLargestBlock = 46000U;
constexpr const char *kHost = "speed.cloudflare.com";
constexpr const char *kUrl =
    "https://speed.cloudflare.com/__down?bytes=65536";

// GTS Root R4 public trust anchor, SHA256:
// 349DFA4058C5E263123B398AE795573C4E1313C83FE68F93556CD5E8031B3C7D
// Source: publicly trusted system CA store; valid until June 2036.
// CA rotation / intermediate changes can make HTTPS fail independently
// from the network. Never disable certificate verification to make a test pass.
constexpr const char kGtsRootR4[] = R"PEM(-----BEGIN CERTIFICATE-----
MIICCTCCAY6gAwIBAgINAgPlwGjvYxqccpBQUjAKBggqhkjOPQQDAzBHMQswCQYD
VQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIG
A1UEAxMLR1RTIFJvb3QgUjQwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAwMDAw
WjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2Vz
IExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjQwdjAQBgcqhkjOPQIBBgUrgQQAIgNi
AATzdHOnaItgrkO4NcWBMHtLSZ37wWHO5t5GvWvVYRg1rkDdc/eJkTBa6zzuhXyi
QHY7qca4R9gq55KRanPpsXI5nymfopjTX15YhmUPoYRlBtHci8nHc8iMai/lxKvR
HYqjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW
BBSATNbrdP9JNqPV2Py1PsVq8JQdjDAKBggqhkjOPQQDAwNpADBmAjEA6ED/g94D
9J+uHXqnLrmvT/aDHQ4thQEd0dlq7A/Cr8deVl5c1RxYIigL9zC2L7F8AjEA8GE8
p/SgguMh1YQdc4acLa/KNJvxn7kjNuK8YAOdgLOaVsjh4rsUecrNIdSUtUlD
-----END CERTIFICATE-----
)PEM";

enum class Status : uint8_t {
    NOT_TESTED,
    WIFI_DOWN,
    CLOCK_NOT_READY,
    DNS_FAIL,
    LOW_MEMORY,
    HTTP_SETUP_FAIL,
    TLS_OR_CONNECT_FAIL,
    HTTP_STATUS_ERROR,
    BODY_ERROR,
    BODY_TOO_LARGE,
    BODY_INCOMPLETE,
    PASS
};

const char *statusName(Status s) {
    switch (s) {
        case Status::NOT_TESTED: return "NOT_TESTED";
        case Status::WIFI_DOWN: return "WIFI_DOWN";
        case Status::CLOCK_NOT_READY: return "CLOCK_NOT_READY";
        case Status::DNS_FAIL: return "DNS_FAIL";
        case Status::LOW_MEMORY: return "LOW_MEMORY";
        case Status::HTTP_SETUP_FAIL: return "HTTP_SETUP_FAIL";
        case Status::TLS_OR_CONNECT_FAIL: return "TLS_OR_CONNECT_FAIL";
        case Status::HTTP_STATUS_ERROR: return "HTTP_STATUS_ERROR";
        case Status::BODY_ERROR: return "BODY_ERROR";
        case Status::BODY_TOO_LARGE: return "BODY_TOO_LARGE";
        case Status::BODY_INCOMPLETE: return "BODY_INCOMPLETE";
        case Status::PASS: return "PASS";
    }
    return "UNKNOWN";
}

struct Result {
    Status status = Status::NOT_TESTED;
    uint32_t dnsMs = 0;
    uint32_t headersMs = 0;
    uint32_t firstBodyMs = 0;
    uint32_t bodyTransferMs = 0;
    uint32_t totalMs = 0;
    uint32_t bytes = 0;
    uint32_t approxKibPerSec = 0;
    int httpCode = 0;
    int httpStreamResult = 0;
};

// HTTPClient::writeToStream() supports both identity and chunked HTTP bodies.
// The stream discards all body content immediately and limits total bytes/time.
class CountingSink : public Stream {
public:
    explicit CountingSink(uint32_t started) : startedMs_(started) {}
    size_t write(uint8_t b) override { return write(&b, 1); }
    size_t write(const uint8_t *buffer, size_t length) override {
        (void)buffer;
        const uint32_t now = millis();
        if (now - startedMs_ > kMaxBodyMs) {
            timeLimitHit = true;
            return 0;
        }
        if (length > kBodyBytes - received) {
            tooLarge = true;
            return 0;
        }
        if (length != 0) {
            if (!gotFirst) {
                gotFirst = true;
                firstAtMs = now;
            }
            received += static_cast<uint32_t>(length);
            lastAtMs = now;
        }
        return length;
    }
    int available() override { return 0; }
    int read() override { return -1; }
    int peek() override { return -1; }
    void flush() override {}

    uint32_t received = 0;
    uint32_t firstAtMs = 0;
    uint32_t lastAtMs = 0;
    bool gotFirst = false;
    bool tooLarge = false;
    bool timeLimitHit = false;

private:
    uint32_t startedMs_;
};

// Returns a source-specific HTTPS result. Does not attempt to infer filtering,
// Telegram reachability, global Internet health, or VPN throughput.
Result run() {
    Result result{};
    if (WiFi.status() != WL_CONNECTED) {
        result.status = Status::WIFI_DOWN;
        return result;
    }
    // TLS certificate dates must be checked against a sane clock. NTP being
    // unavailable means this test is unmeasurable, NOT that HTTPS is blocked.
    if (time(nullptr) < 1700000000) {
        result.status = Status::CLOCK_NOT_READY;
        return result;
    }
    if (ESP.getFreeHeap() < kMinFreeHeap ||
        heap_caps_get_largest_free_block(MALLOC_CAP_8BIT) < kMinLargestBlock) {
        result.status = Status::LOW_MEMORY;
        return result;
    }

    const uint32_t startMs = millis();
    IPAddress serverIp;
    const uint32_t dnsStart = millis();
    const bool dnsOk = WiFi.hostByName(kHost, serverIp) == 1;
    result.dnsMs = millis() - dnsStart;
    if (!dnsOk) {
        result.status = Status::DNS_FAIL;
        result.totalMs = millis() - startMs;
        return result;
    }

    // SNI and HTTP Host must both use the hostname (not the resolved IP).
    WiFiClientSecure tls;
    tls.setCACert(kGtsRootR4);
    tls.setHandshakeTimeout(7);
    // HTTPClient::setTimeout below is in milliseconds and sets the
    // underlying WiFiClientSecure read timeout in seconds as required.

    HTTPClient http;
    http.setConnectTimeout(7000);
    http.setTimeout(4000);
    http.setReuse(false);
    if (!http.begin(tls, kUrl)) {
        result.status = Status::HTTP_SETUP_FAIL;
        result.totalMs = millis() - startMs;
        return result;
    }
    http.addHeader("Accept-Encoding", "identity");
    http.addHeader("Cache-Control", "no-store");
    // Deliberately do not enable automatic redirects.
    const uint32_t requestStartMs = millis();
    result.httpCode = http.GET();
    result.headersMs = millis() - requestStartMs;
    if (result.httpCode < 0) {
        result.status = Status::TLS_OR_CONNECT_FAIL;
        http.end();
        result.totalMs = millis() - startMs;
        return result;
    }
    if (result.httpCode != HTTP_CODE_OK) {
        result.status = Status::HTTP_STATUS_ERROR;
        http.end();
        result.totalMs = millis() - startMs;
        return result;
    }
    // Reject a clearly mismatched Content-Length; chunked/no length is okay.
    const int expectedSize = http.getSize();
    if (expectedSize > static_cast<int>(kBodyBytes)) {
        result.status = Status::BODY_TOO_LARGE;
        http.end();
        result.totalMs = millis() - startMs;
        return result;
    }
    if (expectedSize >= 0 && expectedSize != static_cast<int>(kBodyBytes)) {
        result.status = Status::BODY_INCOMPLETE;
        http.end();
        result.totalMs = millis() - startMs;
        return result;
    }

    CountingSink sink(millis());
    result.httpStreamResult = http.writeToStream(&sink);
    result.bytes = sink.received;
    result.firstBodyMs = sink.gotFirst ? sink.firstAtMs - requestStartMs : 0;
    result.bodyTransferMs = sink.gotFirst ? sink.lastAtMs - sink.firstAtMs : 0;
    result.totalMs = millis() - startMs;
    http.end();
    if (sink.tooLarge) result.status = Status::BODY_TOO_LARGE;
    else if (sink.timeLimitHit || result.httpStreamResult < 0)
        result.status = Status::BODY_ERROR;
    else if (result.httpStreamResult != static_cast<int>(kBodyBytes) ||
             sink.received != kBodyBytes)
        result.status = Status::BODY_INCOMPLETE;
    else {
        result.status = Status::PASS;
        // Approximation from body chunks only; 64 KiB is not a full-speed test.
        const uint32_t ms = result.bodyTransferMs > 0
            ? result.bodyTransferMs : 1;
        result.approxKibPerSec = static_cast<uint32_t>(
            (static_cast<uint64_t>(kBodyBytes) * 1000ULL) /
            (static_cast<uint64_t>(ms) * 1024ULL));
    }
    return result;
}

} // namespace HttpsQuality

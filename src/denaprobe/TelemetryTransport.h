#pragma once
// DPT/1 HTTPS transport. Caller runs this ONLY in a serialized worker,
// never simultaneously with the memory-heavy SSH/HTTPS measurement worker.
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <mbedtls/md.h>
#include <mbedtls/base64.h>
#include <time.h>
#include <string.h>
#include <limits.h>
#include "TelemetryCodec.h"
#include "TelemetryAck.h"

#ifndef PROBE_DPT_ENABLED
#define PROBE_DPT_ENABLED 0
#endif
#ifndef PROBE_DPT_DEVICE_ID
#define PROBE_DPT_DEVICE_ID ""
#endif
#ifndef PROBE_DPT_KEY_ID
#define PROBE_DPT_KEY_ID ""
#endif
#ifndef PROBE_DPT_SECRET_HEX
#define PROBE_DPT_SECRET_HEX ""
#endif
#ifndef PROBE_DPT_API_URL
#define PROBE_DPT_API_URL ""
#endif
#ifndef PROBE_DPT_CA_PEM
#define PROBE_DPT_CA_PEM ""
#endif
#ifndef PROBE_DPT_TARGET_ID
#define PROBE_DPT_TARGET_ID 1
#endif

namespace DenaProbe { namespace Dpt {
enum class Delivery : uint8_t { ACCEPTED, DUPLICATE, HISTORY_ONLY, RETRY, REJECT, SECURITY };
struct DeliveryResult {
    Delivery kind = Delivery::RETRY;
    uint32_t sequence = 0;
    int httpStatus = 0;
    uint32_t retryAfterMs = 0;
};

inline int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
inline bool decodeSecret(const char *hex, unsigned char key[32]) {
    if (!hex || strlen(hex) != 64) return false;
    for (int i = 0; i < 32; ++i) {
        int a = hexNibble(hex[2 * i]);
        int b = hexNibble(hex[2 * i + 1]);
        if (a < 0 || b < 0) return false;
        key[i] = static_cast<unsigned char>((a << 4) | b);
    }
    return true;
}

inline bool validSettings() {
    if (!PROBE_DPT_ENABLED || !validId(PROBE_DPT_DEVICE_ID) ||
        strlen(PROBE_DPT_KEY_ID) < 1 || strlen(PROBE_DPT_KEY_ID) > 32 ||
        PROBE_DPT_TARGET_ID < 1 || PROBE_DPT_TARGET_ID > 65535 ||
        strlen(PROBE_DPT_CA_PEM) < 100) return false;
    for (const char *p = PROBE_DPT_KEY_ID; *p; ++p)
        if (!( (*p >= 'a' && *p <= 'z') ||
               (*p >= 'A' && *p <= 'Z') ||
               (*p >= '0' && *p <= '9') ||
               *p == '-' || *p == '_')) return false;
    const char *url = PROBE_DPT_API_URL;
    constexpr const char *prefix = "https://";
    constexpr const char *suffix = "/api/dpt/v1/telemetry";
    const size_t len = strlen(url), slen = strlen(suffix);
    if (len <= strlen(prefix) + slen ||
        strncmp(url, prefix, strlen(prefix)) != 0 ||
        strcmp(url + len - slen, suffix) != 0) return false;
    // Only canonical HTTPS URLs on a DNS hostname, no credentials/query.
    for (const char *p = url + strlen(prefix); p < url + len - slen; ++p)
        if (*p == '@' || *p == '?' || *p == '#' || *p == '/') return false;
    unsigned char secret[32]{};
    const bool good = decodeSecret(PROBE_DPT_SECRET_HEX, secret);
    memset(secret, 0, sizeof(secret));
    return good;
}

inline bool signature(const Message &message, uint64_t sentUptime,
                      char outSignature[64]) {
    unsigned char secret[32]{};
    if (!decodeSecret(PROBE_DPT_SECRET_HEX, secret)) return false;
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) { memset(secret, 0, sizeof(secret)); return false; }
    unsigned char digest[32]{};
    const int hashRc = mbedtls_md(md,
        reinterpret_cast<const unsigned char *>(message.body),
        message.length, digest);
    if (hashRc != 0) { memset(secret, 0, sizeof(secret)); return false; }
    char hashHex[65]{};
    constexpr char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        hashHex[2 * i] = hex[digest[i] >> 4];
        hashHex[2 * i + 1] = hex[digest[i] & 15];
    }
    char toSign[240]{};
    const int n = snprintf(toSign, sizeof(toSign),
        "DPT1\nPOST\n/api/dpt/v1/telemetry\n%s\n%s\n%llu\n%s",
        PROBE_DPT_DEVICE_ID, PROBE_DPT_KEY_ID,
        static_cast<unsigned long long>(sentUptime), hashHex);
    if (n < 0 || static_cast<size_t>(n) >= sizeof(toSign)) {
        memset(secret, 0, sizeof(secret)); return false;
    }
    unsigned char mac[32]{};
    const int macRc = mbedtls_md_hmac(md, secret, sizeof(secret),
        reinterpret_cast<const unsigned char *>(toSign), n, mac);
    memset(secret, 0, sizeof(secret));
    memset(toSign, 0, sizeof(toSign));
    if (macRc != 0) return false;
    size_t b64Length = 0;
    unsigned char encoded[64]{};
    if (mbedtls_base64_encode(encoded, sizeof(encoded), &b64Length,
                              mac, sizeof(mac)) != 0) return false;
    while (b64Length && encoded[b64Length - 1] == '=') --b64Length;
    if (b64Length >= 64) return false;
    for (size_t i = 0; i < b64Length; ++i) {
        const char c = static_cast<char>(encoded[i]);
        outSignature[i] = c == '+' ? '-' : c == '/' ? '_' : c;
    }
    outSignature[b64Length] = '\0';
    return true;
}

// Strict parser of the exact DPT/1 ACK schema (un-ordered JSON keys).
// Reject duplicate/unknown keys, escaped IDs, missing fields, trailing data,
// noncanonical/overflowing numbers. No dependency on another JSON library.
// Limit arbitrary response size even for chunked/lengthless JSON ACKs.
class AckSink : public Stream {
public:
    size_t write(uint8_t b) override { return write(&b, 1); }
    size_t write(const uint8_t *data, size_t length) override {
        if (length > 192 - size_) { overflow_ = true; return 0; }
        memcpy(body_ + size_, data, length);
        size_ += length;
        body_[size_] = '\0';
        return length;
    }
    int available() override { return 0; }
    int read() override { return -1; }
    int peek() override { return -1; }
    void flush() override {}
    const char *body() const { return body_; }
    size_t size() const { return size_; }
    bool overflowed() const { return overflow_; }
private:
    char body_[193]{};
    size_t size_ = 0;
    bool overflow_ = false;
};

inline DeliveryResult deliver(const Message &message, uint64_t sendUptime,
                              const char *bootId) {
    DeliveryResult result{};
    result.sequence = message.sequence;
    if (WiFi.status() != WL_CONNECTED || time(nullptr) < 1700000000 ||
        sendUptime < message.completedUptime) return result;
    if (!validSettings()) { result.kind = Delivery::SECURITY; return result; }
    char sign[64]{};
    if (!signature(message, sendUptime, sign)) {
        result.kind = Delivery::SECURITY; return result;
    }
    WiFiClientSecure tls;
    tls.setCACert(PROBE_DPT_CA_PEM); // Never use setInsecure().
    tls.setHandshakeTimeout(6);
    HTTPClient http;
    http.setConnectTimeout(5000);
    http.setTimeout(4000);
    http.setReuse(false);
    http.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);
    if (!http.begin(tls, PROBE_DPT_API_URL)) return result;
    const char *retryKeys[] = {"Retry-After"};
    http.collectHeaders(retryKeys, 1);
    char uptime[24]{};
    snprintf(uptime, sizeof(uptime), "%llu",
             static_cast<unsigned long long>(sendUptime));
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-DPT-Device", PROBE_DPT_DEVICE_ID);
    http.addHeader("X-DPT-Key-Id", PROBE_DPT_KEY_ID);
    http.addHeader("X-DPT-Sent-Uptime-Ms", uptime);
    http.addHeader("X-DPT-Signature", sign);
    memset(sign, 0, sizeof(sign));
    const int status = http.POST(reinterpret_cast<uint8_t *>(
        const_cast<char *>(message.body)), message.length);
    result.httpStatus = status;
    if (status == 200) {
        const int declaredLength = http.getSize();
        if (declaredLength > 192) {
            result.kind = Delivery::SECURITY;
        } else {
            AckSink sink;
            const int received = http.writeToStream(&sink);
            if (received >= 0 && !sink.overflowed() &&
                received == static_cast<int>(sink.size()) && sink.size() > 0) {
                uint8_t ack = 255;
                AckParser parser(sink.body());
                if (parser.matches(bootId, message.sequence, ack)) {
                    result.kind = ack == 0 ? Delivery::ACCEPTED :
                        ack == 1 ? Delivery::DUPLICATE : Delivery::HISTORY_ONLY;
                } else result.kind = Delivery::SECURITY;
            } // A truncated network body is retriable, never an ACK.
        }
    } else if (status == 400 || status == 422) {
        result.kind = Delivery::REJECT;
    } else if (status == 401 || status == 403 || status == 409 ||
               status == 413 || (status >= 300 && status < 400 && status != 302)) {
        result.kind = Delivery::SECURITY;
    } else if (status == 302) {
        result.kind = Delivery::SECURITY; // Do not follow redirects.
    }
    if (status == 429 || status >= 500) {
        const String retry = http.header("Retry-After");
        if (!retry.isEmpty() && retry.length() <= 5) {
            uint32_t seconds = 0;
            bool numeric = true;
            for (size_t i = 0; i < retry.length(); ++i) {
                if (retry[i] < '0' || retry[i] > '9') {
                    numeric = false; break;
                }
                seconds = seconds * 10UL + static_cast<uint32_t>(retry[i] - '0');
            }
            if (numeric && seconds <= 300UL)
                result.retryAfterMs = seconds * 1000UL;
        }
    }
    http.end();
    return result;
}
} } // namespace DenaProbe::Dpt

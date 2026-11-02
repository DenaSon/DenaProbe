#pragma once
// DPT/1 measurement encoder and bounded volatile journal. No network I/O.
// The instrument produces raw stage/timing codes; incidents are server-only.
#include <Arduino.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "ProbeTypes.h"

namespace DenaProbe { namespace Dpt {
constexpr size_t kMaxBody = 1024;
constexpr uint8_t kQueueCapacity = 12;
constexpr uint32_t kNormalFlushMs = 90000UL;
constexpr uint32_t kMaxReplayAgeMs = 360000UL; // Older messages remain history, never live hints.

struct Message {
    char body[kMaxBody + 1]{};
    uint16_t length = 0;
    uint32_t sequence = 0;
    uint64_t completedUptime = 0;
    uint8_t kind = 0;
    bool urgent = false;
};

class ExtendedUptime {
public:
    void update(uint32_t raw) {
        if (initialized_ && raw < last_) high_ += (1ULL << 32);
        initialized_ = true;
        last_ = raw;
    }
    uint64_t now() const { return high_ + last_; }
    // Events are consumed shortly after the worker stamps their completion.
    uint64_t at(uint32_t completedRaw) const {
        return now() - static_cast<uint32_t>(last_ - completedRaw);
    }
private:
    uint64_t high_ = 0;
    uint32_t last_ = 0;
    bool initialized_ = false;
};

class Writer {
public:
    explicit Writer(Message &message) : item_(message) {}
    bool add(const char *format, ...) {
        if (!ok_) return false;
        va_list args;
        va_start(args, format);
        const int n = vsnprintf(item_.body + used_, kMaxBody + 1 - used_, format, args);
        va_end(args);
        if (n < 0 || static_cast<size_t>(n) >= kMaxBody + 1 - used_) {
            ok_ = false; return false;
        }
        used_ += static_cast<size_t>(n);
        item_.length = static_cast<uint16_t>(used_);
        return true;
    }
    bool good() const { return ok_ && used_ <= kMaxBody; }
private:
    Message &item_;
    size_t used_ = 0;
    bool ok_ = true;
};

inline uint16_t code(Code c) {
    switch (c) {
        case Code::PASS: return 1;
        case Code::WIFI_LOST: return 10;
        case Code::DNS_FAIL: return 20;
        case Code::SSH_CONNECT_TIMEOUT: return 30;
        case Code::SSH_CONNECT_ERROR: return 31;
        case Code::HOST_KEY_ERROR: return 40;
        case Code::HOST_KEY_MISMATCH: return 41;
        case Code::SERVICE_ACCEPT_TIMEOUT: return 50;
        case Code::SERVICE_REQUEST_ERROR: return 51;
        case Code::SESSION_ALLOC_FAILED: return 90;
        case Code::SSH_OPTIONS_FAILED: return 91;
    }
    return 0;
}

inline uint8_t observations(const Result &r) {
    const StageTrace &s = r.stages;
    uint8_t bits = 0;
    if (s.bannerMs >= 0) bits |= 1U;
    if (s.kexInitTxMs >= 0) bits |= 2U;
    if (s.kexInitRxMs >= 0) bits |= 4U;
    if (s.algorithmsMs >= 0) bits |= 8U;
    if (s.newkeysRxMs >= 0) bits |= 16U;
    if (s.transportVerified) bits |= 32U;
    if (s.transportVerified && (r.code == Code::PASS ||
        r.code == Code::SERVICE_ACCEPT_TIMEOUT ||
        r.code == Code::SERVICE_REQUEST_ERROR)) bits |= 64U;
    if (r.code == Code::PASS) bits |= 128U;
    return bits;
}

inline uint16_t stage(const Result &r) {
    switch (r.code) {
        case Code::WIFI_LOST: return 10;
        case Code::DNS_FAIL: return 20;
        case Code::SESSION_ALLOC_FAILED: return 90;
        case Code::SSH_OPTIONS_FAILED: return 21;
        case Code::HOST_KEY_ERROR:
        case Code::HOST_KEY_MISMATCH: return 40;
        case Code::SERVICE_ACCEPT_TIMEOUT: return 51;
        case Code::SERVICE_REQUEST_ERROR: return 50;
        case Code::PASS: return 52;
        default: break;
    }
    if (r.stages.newkeysRxMs >= 0) return 35;
    if (r.stages.algorithmsMs >= 0) return 34;
    if (r.stages.kexInitRxMs >= 0) return 33;
    if (r.stages.kexInitTxMs >= 0) return 32;
    if (r.stages.bannerMs >= 0) return 31;
    return 30;
}

inline uint16_t httpsCode(HttpsQuality::Status s) {
    switch (s) {
        case HttpsQuality::Status::NOT_TESTED: return 0;
        case HttpsQuality::Status::PASS: return 1;
        case HttpsQuality::Status::SLOW_64K_SAMPLE_SUSPECT: return 2;
        case HttpsQuality::Status::WIFI_DOWN: return 10;
        case HttpsQuality::Status::CLOCK_NOT_READY: return 11;
        case HttpsQuality::Status::LOW_MEMORY: return 12;
        case HttpsQuality::Status::DNS_FAIL: return 20;
        case HttpsQuality::Status::TLS_OR_CONNECT_FAIL: return 30;
        case HttpsQuality::Status::HTTP_SETUP_FAIL: return 31;
        case HttpsQuality::Status::HTTP_STATUS_ERROR: return 32;
        case HttpsQuality::Status::BODY_ERROR: return 40;
        case HttpsQuality::Status::BODY_TOO_LARGE: return 41;
        case HttpsQuality::Status::BODY_INCOMPLETE: return 42;
    }
    return 0;
}

inline bool validId(const char *id) {
    if (!id) return false;
    const size_t n = strlen(id);
    if (n < 2 || n > 32 || id[0] < 'a' || id[0] > 'z') return false;
    for (size_t i = 1; i < n; ++i) {
        if (!((id[i] >= 'a' && id[i] <= 'z') ||
              (id[i] >= '0' && id[i] <= '9') ||
              id[i] == '-' || id[i] == '_')) return false;
    }
    return true;
}

class Journal {
public:
    bool begin(const char *deviceId, const char *bootId, uint16_t targetId,
               uint64_t bootUptime, bool wifiUp) {
        if (!validId(deviceId) || !bootId || strlen(bootId) != 32 ||
            targetId == 0) return false;
        for (size_t i = 0; i < 32; ++i) {
            if (!((bootId[i] >= '0' && bootId[i] <= '9') ||
                  (bootId[i] >= 'a' && bootId[i] <= 'f'))) return false;
        }
        strcpy(device_, deviceId);
        strcpy(boot_, bootId);
        targetId_ = targetId;
        nextSequence_ = 1;
        count_ = 0;
        dropped_ = 0;
        Message m{};
        m.sequence = next();
        m.kind = 3;
        m.completedUptime = bootUptime;
        m.urgent = true;
        Writer w(m);
        w.add("{\"v\":1,\"id\":\"%s\",\"b\":\"%s\",\"q\":%lu,"
              "\"u\":%llu,\"k\":3,\"w\":%u}",
              device_, boot_, static_cast<unsigned long>(m.sequence),
              static_cast<unsigned long long>(bootUptime), wifiUp ? 1U : 0U);
        return w.good() && insert(m);
    }

    bool pushSsh(const Result &r, uint64_t completedUptime, bool wifiUp,
                 const HttpsQuality::Result *https = nullptr,
                 uint64_t httpsUptime = 0) {
        if (nextSequence_ == 0) return false;
        Message m{};
        m.sequence = next();
        m.kind = 1;
        m.completedUptime = https ? httpsUptime : completedUptime;
        m.urgent = r.code != Code::PASS;
        Writer w(m);
        w.add("{\"v\":1,\"id\":\"%s\",\"b\":\"%s\",\"q\":%lu,"
              "\"u\":%llu,\"k\":1,\"t\":%u,\"w\":%u",
              device_, boot_, static_cast<unsigned long>(m.sequence),
              static_cast<unsigned long long>(completedUptime),
              static_cast<unsigned int>(targetId_), wifiUp ? 1U : 0U);
        if (wifiUp && r.wifiRssiDbm >= -127 && r.wifiRssiDbm <= -1)
            w.add(",\"r\":%d", static_cast<int>(r.wifiRssiDbm));
        w.add(",\"s\":%u,\"p\":%u,\"o\":%u", code(r.code), stage(r),
              static_cast<unsigned int>(observations(r)));
        if (r.code != Code::WIFI_LOST) w.add(",\"d\":%lu",
            static_cast<unsigned long>(r.dnsMs));
        if (r.stages.startedAt != 0 || r.transportMs > 0)
            w.add(",\"x\":%lu", static_cast<unsigned long>(r.transportMs));
        if (r.code == Code::PASS ||
            r.code == Code::SERVICE_ACCEPT_TIMEOUT ||
            r.code == Code::SERVICE_REQUEST_ERROR)
            w.add(",\"a\":%lu", static_cast<unsigned long>(r.serviceMs));
        if (https) {
            w.add(",\"h\":{\"c\":%u,\"u\":%llu", httpsCode(https->status),
                  static_cast<unsigned long long>(httpsUptime));
            // Do not invent measured-zero values when HTTP was not attempted.
            const bool attempted = https->status != HttpsQuality::Status::NOT_TESTED &&
                https->status != HttpsQuality::Status::WIFI_DOWN &&
                https->status != HttpsQuality::Status::CLOCK_NOT_READY &&
                https->status != HttpsQuality::Status::LOW_MEMORY;
            if (attempted) {
                w.add(",\"ms\":%lu,\"ds\":%lu",
                    static_cast<unsigned long>(https->totalMs),
                    static_cast<unsigned long>(https->dnsMs));
                if (https->httpCode >= 100 && https->httpCode <= 599)
                    w.add(",\"hc\":%d,\"hd\":%lu",
                          https->httpCode, static_cast<unsigned long>(https->headersMs));
                if (https->bytes > 0 || https->status == HttpsQuality::Status::PASS ||
                    https->status == HttpsQuality::Status::SLOW_64K_SAMPLE_SUSPECT) {
                    w.add(",\"n\":%lu,\"bt\":%lu,\"fb\":%lu",
                          static_cast<unsigned long>(https->bytes),
                          static_cast<unsigned long>(https->bodyTransferMs),
                          static_cast<unsigned long>(https->firstBodyMs));
                }
            }
            w.add("}");
        }
        w.add("}");
        return w.good() && insert(m);
    }

    bool pushLocal(uint16_t localCode, uint64_t completedUptime, bool wifiUp,
                   bool urgent = true) {
        if (nextSequence_ == 0 || localCode < 90 || localCode > 96) return false;
        Message m{};
        m.sequence = next();
        m.kind = 2;
        m.urgent = urgent;
        m.completedUptime = completedUptime;
        Writer w(m);
        w.add("{\"v\":1,\"id\":\"%s\",\"b\":\"%s\",\"q\":%lu,"
              "\"u\":%llu,\"k\":2,\"w\":%u,\"s\":%u}",
              device_, boot_, static_cast<unsigned long>(m.sequence),
              static_cast<unsigned long long>(completedUptime),
              wifiUp ? 1U : 0U, static_cast<unsigned int>(localCode));
        return w.good() && insert(m);
    }

    uint8_t size() const { return count_; }
    uint32_t dropped() const { return dropped_; }
    const char *bootId() const { return boot_; }
    const char *deviceId() const { return device_; }

    // Strict FIFO: emit the oldest surviving sequence first, including BOOT.
    // Jumping ahead to a newer sample caused the R2-C field failure:
    // old samples were ACKed HISTORY_ONLY and fresh HTTPS never became live.
    // Urgency starts an EARLY drain of the queue; it never reorders events.
    int choose() const { return count_ ? 0 : -1; }
    bool hasUrgent() const {
        for (uint8_t i = 0; i < count_; ++i)
            if (messages_[i].urgent) return true;
        return false;
    }
    const Message *at(uint8_t index) const {
        return index < count_ ? &messages_[index] : nullptr;
    }
    void remove(uint32_t sequence) {
        for (uint8_t i = 0; i < count_; ++i) {
            if (messages_[i].sequence == sequence) {
                for (uint8_t j = i + 1; j < count_; ++j)
                    messages_[j - 1] = messages_[j];
                --count_;
                return;
            }
        }
    }
    // Nonrecoverable payload errors drop this one record and leave a gap.
    void discard(uint32_t sequence) { remove(sequence); ++dropped_; }
private:
    uint32_t next() {
        const uint32_t q = nextSequence_;
        if (nextSequence_ == UINT32_MAX) nextSequence_ = 0; // Reboot required.
        else ++nextSequence_;
        return q;
    }
    bool insert(const Message &m) {
        if (count_ == kQueueCapacity) {
            // Never evict a pending BOOT marker.
            const uint8_t victim = messages_[0].kind == 3 ? 1 : 0;
            for (uint8_t i = victim + 1; i < count_; ++i)
                messages_[i - 1] = messages_[i];
            --count_;
            ++dropped_;
        }
        messages_[count_++] = m;
        return true;
    }
    Message messages_[kQueueCapacity]{};
    uint8_t count_ = 0;
    uint32_t nextSequence_ = 1;
    uint32_t dropped_ = 0;
    uint16_t targetId_ = 1;
    char device_[33]{};
    char boot_[33]{};
};
} } // namespace DenaProbe::Dpt

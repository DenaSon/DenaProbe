#pragma once
// Strict DPT/1 ACK validation, independent of TLS/crypto and host-testable.
#include <stdint.h>
#include <limits.h>
#include <string.h>
namespace DenaProbe { namespace Dpt {
class AckParser {
public:
    explicit AckParser(const char *p) : p_(p ? p : "") {}
    bool matches(const char *boot, uint32_t q, uint8_t &ack) {
        bool v = false, b = false, seq = false, haveAck = false;
        if (!take('{')) return false;
        for (int count = 0; count < 4; ++count) {
            char key[12]{};
            if (!keyString(key, sizeof(key)) || !take(':')) return false;
            if (strcmp(key, "v") == 0 && !v) {
                uint64_t n;
                if (!number(n) || n != 1) return false;
                v = true;
            } else if (strcmp(key, "b") == 0 && !b) {
                char id[40]{};
                if (!keyString(id, sizeof(id)) || strcmp(id, boot) != 0) return false;
                b = true;
            } else if (strcmp(key, "q") == 0 && !seq) {
                uint64_t n;
                if (!number(n) || n != q) return false;
                seq = true;
            } else if (strcmp(key, "ack") == 0 && !haveAck) {
                if (!take('{')) return false;
                char r[12]{};
                uint64_t n;
                if (!keyString(r, sizeof(r)) || strcmp(r, "r") != 0 ||
                    !take(':') || !number(n) || n > 2 || !take('}')) return false;
                ack = static_cast<uint8_t>(n);
                haveAck = true;
            } else return false;
            spaces();
            if (count != 3 && *p_ == ',') { ++p_; continue; }
            if (count == 3 && *p_ == '}') {
                ++p_;
                spaces();
                return v && b && seq && haveAck && *p_ == '\0';
            }
            return false;
        }
        return false;
    }
private:
    void spaces() {
        while (*p_ == ' ' || *p_ == '\r' || *p_ == '\n' || *p_ == '\t') ++p_;
    }
    bool take(char c) { spaces(); if (*p_ != c) return false; ++p_; return true; }
    bool keyString(char *out, size_t capacity) {
        if (!take('"')) return false;
        size_t pos = 0;
        while (*p_ && *p_ != '"') {
            unsigned char c = static_cast<unsigned char>(*p_);
            if (c < 0x20 || c == '\\' || pos + 1 >= capacity) return false;
            out[pos++] = *p_++;
        }
        if (*p_ != '"') return false;
        ++p_;
        out[pos] = '\0';
        return true;
    }
    bool number(uint64_t &out) {
        spaces();
        if (*p_ < '0' || *p_ > '9') return false;
        if (*p_ == '0' && p_[1] >= '0' && p_[1] <= '9') return false;
        uint64_t v = 0;
        while (*p_ >= '0' && *p_ <= '9') {
            const unsigned d = static_cast<unsigned>(*p_ - '0');
            if (v > (UINT64_MAX - d) / 10ULL) return false;
            v = v * 10ULL + d;
            ++p_;
        }
        out = v;
        return true;
    }
    const char *p_;
};
} } // namespace DenaProbe::Dpt

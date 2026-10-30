#pragma once
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <vector>

// Deterministic peripherals only. The tests include the real production
// probe, deadline, state, scheduler, queue and orchestration code.
namespace Fake {
inline uint32_t now = 0;
inline bool wifi = true;
inline uint32_t dropAt = UINT32_MAX;
inline int dnsCalls = 0, dropOnDns = 0;
inline bool edgeDns = true, controlDns = true;
inline bool tlsConnect = true, badPin = false;
inline int connects = 0, stops = 0, serviceCalls = 0;
inline std::string tlsHostname, tlsRoot;
inline uint32_t heap = 200000;
inline uint32_t largest = 100000;
inline int transportRc = 0, serviceRc = 0;
enum class Response { NORMAL, SILENT_BODY, DRIP_BODY, SILENT_HEADERS,
                      DRIP_HEADERS, SILENT_CHUNK_HEADER };
inline Response response = Response::NORMAL;
inline int httpCode = 200, contentLength = 65536, payloadSize = 65536;
inline uint32_t bodyDelay = 20;
inline std::vector<std::string> logs;
inline int taskCreates = 0, taskDeletes = 0;
inline bool taskAlloc = true;
inline void (*worker)(void *) = nullptr;
inline void tick(uint32_t ms = 1) {
    now += ms;
    if (dropAt != UINT32_MAX && now >= dropAt) wifi = false;
}
inline void reset() {
    now = 0; wifi = true; dropAt = UINT32_MAX;
    dnsCalls = dropOnDns = connects = stops = serviceCalls = 0;
    edgeDns = controlDns = tlsConnect = true; badPin = false;
    tlsHostname.clear(); tlsRoot.clear(); heap = 200000; largest = 100000;
    transportRc = serviceRc = 0; response = Response::NORMAL;
    httpCode = 200; contentLength = payloadSize = 65536; bodyDelay = 20;
    logs.clear(); taskCreates = taskDeletes = 0; taskAlloc = true; worker = nullptr;
}
}
using String = std::string;
inline uint32_t millis() { return Fake::now; }
inline void delay(uint32_t ms) { Fake::tick(ms); }
constexpr int HIGH = 1, LOW = 0, OUTPUT = 1;
inline void pinMode(int, int) {}
inline void digitalWrite(int, int) {}
struct SerialStub {
    void begin(int) {}
    void println(const char *s) { Fake::logs.emplace_back(s); }
    template <class... Args> void printf(const char *fmt, Args... args) {
        char line[2048]; std::snprintf(line, sizeof(line), fmt, args...);
        Fake::logs.emplace_back(line);
    }
};
inline SerialStub Serial;
struct EspStub {
    uint32_t getFreeHeap() { return Fake::heap; }
    uint32_t getMinFreeHeap() { return Fake::heap; }
};
inline EspStub ESP;
class Stream {
public:
    virtual ~Stream() = default;
    virtual size_t write(uint8_t) = 0;
    virtual size_t write(const uint8_t *, size_t) = 0;
    virtual int available() = 0;
    virtual int read() = 0;
    virtual int peek() = 0;
    virtual void flush() = 0;
    void setTimeout(uint32_t ms) { timeout_ = ms; }
    uint32_t getTimeout() const { return timeout_; }
    // Model Arduino Stream's per-character timeout: dripping bytes reset it.
    String readStringUntil(char terminator) {
        String result;
        for (;;) {
            uint32_t start = millis();
            int c;
            do { c = read(); }
            while (c < 0 && millis() - start < timeout_);
            if (c < 0 || c == terminator) return result;
            result += static_cast<char>(c);
        }
    }
private:
    uint32_t timeout_ = 4000;
};

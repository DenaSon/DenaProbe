#pragma once
#include <cstddef>
#include <cstdint>

namespace DenaProbe {
// Guard the SOURCE of HTTPClient reads, not only its destination Stream.
// HTTPClient can wait without ever writing to the sink (empty response,
// chunk headers, or a stalled body). These virtual entry points are also
// used by Stream::readStringUntil and NetworkClient::readBytes.
// Runtime supplies now() and linkUp(); Base owns and closes its own socket.
template <class Base, class Runtime>
class DeadlineClient : public Base {
public:
    void arm(uint32_t durationMs) {
        startedAt_ = Runtime::now();
        durationMs_ = durationMs;
        armed_ = true;
    }
    bool deadlineExceeded() const { return timedOut_; }
    bool linkLost() const { return linkLost_; }

    uint8_t connected() override {
        return allowed() ? Base::connected() : 0;
    }
    int available() override {
        return allowed() ? Base::available() : 0;
    }
    int read() override { return allowed() ? Base::read() : -1; }
    int read(uint8_t *buffer, size_t size) override {
        return allowed() ? Base::read(buffer, size) : -1;
    }
    int peek() override { return allowed() ? Base::peek() : -1; }

protected:
    bool allowed() {
        if (!timedOut_ && !linkLost_) {
            linkLost_ = !Runtime::linkUp();
            timedOut_ = armed_ &&
                static_cast<uint32_t>(Runtime::now() - startedAt_) >= durationMs_;
            if (timedOut_ || linkLost_) {
                // Same worker closes TLS normally; never delete a crypto task
                // or touch its socket concurrently from the Arduino loop.
                Base::stop();
                // End a Stream::timedRead already waiting for one character.
                Base::setTimeout(0);
            }
        }
        return !timedOut_ && !linkLost_;
    }

private:
    uint32_t startedAt_ = 0;
    uint32_t durationMs_ = 0;
    bool armed_ = false;
    bool timedOut_ = false;
    bool linkLost_ = false;
};
} // namespace DenaProbe

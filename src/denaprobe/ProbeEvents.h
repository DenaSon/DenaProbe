#pragma once
#include <Arduino.h>
#include <type_traits>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include "ProbeTypes.h"

namespace DenaProbe {
enum class ProbeEventKind : uint8_t { SSH_RESULT, HTTPS_RESULT };

// Both payloads are POD-like scalars (no String or pointers). Exactly one
// field is meaningful depending on kind. Worker completion is explicit.
struct ProbeEvent {
    ProbeEventKind kind = ProbeEventKind::SSH_RESULT;
    bool workerFinished = false;
    uint32_t completedAtMs = 0;
    Result ssh{};
    HttpsQuality::Result https{};
};

static_assert(std::is_trivially_copyable<ProbeEvent>::value,
              "FreeRTOS queues copy event bytes; ProbeEvent must remain trivially copyable");

class ProbeEventQueue {
public:
    bool begin() {
        handle_ = xQueueCreate(2, sizeof(ProbeEvent));
        return handle_ != nullptr;
    }
    bool receive(ProbeEvent &out) {
        return handle_ && xQueueReceive(handle_, &out, 0) == pdTRUE;
    }
    void publish(const ProbeEvent &event) {
        // Deliberate lossless back-pressure: producer blocks until the main
        // loop consumes an event. If the main loop stalls, existing 55s
        // worker watchdog identifies a local fault rather than losing data.
        xQueueSend(handle_, &event, portMAX_DELAY);
    }
private:
    QueueHandle_t handle_ = nullptr;
};
} // namespace DenaProbe

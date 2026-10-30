#pragma once
#include "FreeRTOS.h"
struct FakeQueue { size_t capacity, itemSize; std::deque<std::vector<uint8_t>> items; };
using QueueHandle_t = FakeQueue *;
inline QueueHandle_t xQueueCreate(size_t capacity, size_t size) {
    static FakeQueue queue;
    queue = {capacity, size, {}};
    return &queue;
}
inline int xQueueSend(QueueHandle_t q, const void *item, int) {
    assert(q->items.size() < q->capacity);
    const auto p = static_cast<const uint8_t *>(item);
    q->items.emplace_back(p, p + q->itemSize); return pdTRUE;
}
inline int xQueueReceive(QueueHandle_t q, void *item, int) {
    if (q->items.empty()) return 0;
    std::memcpy(item, q->items.front().data(), q->itemSize);
    q->items.pop_front(); return pdTRUE;
}

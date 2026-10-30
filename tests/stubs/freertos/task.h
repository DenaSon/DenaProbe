#pragma once
#include "FreeRTOS.h"
inline void vTaskDelay(uint32_t n) { Fake::tick(n); }
inline void vTaskDelete(void *) { ++Fake::taskDeletes; }
inline uint32_t uxTaskGetStackHighWaterMark(void *) { return 10000; }
inline int xTaskCreatePinnedToCore(void (*worker)(void *), const char *, uint32_t,
                                  void *, int, void *, int) {
    ++Fake::taskCreates; Fake::worker = worker; return Fake::taskAlloc ? pdPASS : 0;
}

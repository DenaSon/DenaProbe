#pragma once
#include "Arduino.h"
using BaseType_t = int;
constexpr int pdTRUE = 1, pdPASS = 1, portMAX_DELAY = -1;
inline uint32_t pdMS_TO_TICKS(uint32_t ms) { return ms; }

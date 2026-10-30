#pragma once
#include "Arduino.h"
constexpr int MALLOC_CAP_8BIT = 1;
inline uint32_t heap_caps_get_largest_free_block(int) { return Fake::largest; }

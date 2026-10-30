#pragma once
#include "../https_quality.h"
namespace DenaProbe {
// Public 64 KiB HTTPS probe with source-side response deadlines.
// This probe never tests NPV tunneling or Telegram connectivity.
inline HttpsQuality::Result runPublicHttpsProbe() {
    return HttpsQuality::run();
}
} // namespace DenaProbe


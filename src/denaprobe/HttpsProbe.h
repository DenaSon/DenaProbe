#pragma once
#include "../https_quality.h"
namespace DenaProbe {
// Preserve the tested public 64 KiB HTTPS implementation byte-for-byte.
// This probe never tests NPV tunneling or Telegram connectivity.
inline HttpsQuality::Result runPublicHttpsProbe() {
    return HttpsQuality::run();
}
} // namespace DenaProbe

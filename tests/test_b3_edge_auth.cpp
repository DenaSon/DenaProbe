// B3 Edge-auth test: real SSH implementation with synthetic libssh only.
#define PROBE_DEEP_ENABLED 1
#define PROBE_DEEP_AUTH_MODE 1
#define PROBE_DEEP_AUTH_ONLY 1
#define PROBE_A2_PIN_ED25519 1
#define PROBE_B3_EDGE_AUTH_ONLY 1
#define PROBE_DEEP_USER "deep-unit-user"
#define PROBE_DEEP_PASSWORD "synthetic-unit-only"
#define PROBE_DEEP_EVERY_N_CYCLES 1
#include "../src/ssh_feasibility_main.cpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
using namespace DenaProbe;
namespace {
bool logged(const char *needle) {
    for (const auto &line : Fake::logs)
        if (line.find(needle) != std::string::npos) return true;
    return false;
}
Dpt::Message encode(const Result &result) {
    Dpt::Journal journal;
    assert(journal.begin("dp-test-01", "0123456789abcdef0123456789abcdef",
                         1, 100, true, 2));
    assert(journal.pushSsh(telemetrySafeResult(result), 1000, true,
                           nullptr, 0, 900, 0, 995));
    const auto *item = journal.at(1);
    assert(item && item->length <= Dpt::kMaxBody);
    return *item;
}
bool has(const Dpt::Message &m, const char *needle) {
    return std::strstr(m.body, needle) != nullptr;
}
}
int main() {
    Fake::reset();
    Result result = runSshTransport();
    assert(result.code == Code::PASS && result.tcp.code == 1);
    assert(result.auth.measured && result.auth.code == 1 &&
           result.auth.elapsedMs > 0);
    assert(!result.deep.measured);
    assert(Fake::authCalls == 1 && Fake::channelOpens == 0);
    assert(Fake::hostKeyEd25519Requested && Fake::userBeforeConnect);
    assert(logged("[edge-auth] mode=PASSWORD | outcome=AUTH_SUCCESS"));
    Dpt::Message m = encode(result);
    assert(has(m, "\"c\":{") && !has(m, "\"z\":"));
#if defined(PROBE_B3_AUTH_WIRE) && PROBE_B3_AUTH_WIRE
    assert(has(m, "\"a\":{\"u\":995,\"s\":1"));
#else
    assert(!has(m, "\"a\":"));
#endif
    assert(!has(m, PROBE_DEEP_PASSWORD) && !has(m, PROBE_DEEP_USER));
    Fake::reset();
    Fake::authRc = SSH_AUTH_DENIED;
    result = runSshTransport();
    assert(result.code == Code::PASS && result.auth.code == 10);
    assert(Fake::authCalls == 1 && Fake::channelOpens == 0);
    m = encode(result);
#if defined(PROBE_B3_AUTH_WIRE) && PROBE_B3_AUTH_WIRE
    assert(has(m, "\"a\":{\"u\":995,\"s\":10"));
#else
    assert(!has(m, "\"a\":"));
#endif
    Fake::reset();
    Fake::authAgain = 1000;
    result = runSshTransport();
    assert(result.code == Code::PASS && result.auth.code == 11);
    assert(result.auth.elapsedMs >= 8000 && Fake::channelOpens == 0);
    Fake::reset();
    Fake::authRc = SSH_ERROR;
    result = runSshTransport();
    assert(result.code == Code::PASS && result.auth.code == 12);
    assert(Fake::channelOpens == 0);
    Fake::reset();
    Fake::badPin = true;
    result = runSshTransport();
    assert(result.code == Code::HOST_KEY_MISMATCH && !result.auth.measured);
    assert(Fake::authCalls == 0 && Fake::channelOpens == 0);
    Fake::reset();
    Fake::authAgain = 1000;
    Fake::dropAt = 100;
    result = runSshTransport();
    assert(result.auth.measured && result.auth.code == 90);
    assert(result.wifiRssiDbm == 0 && Fake::channelOpens == 0);
    std::cout << "PASS B3 Edge auth success/rejected/timeout/error/pin/WiFi, "
              << "no forwarding, wire=" << PROBE_B3_AUTH_WIRE << "\n";
}

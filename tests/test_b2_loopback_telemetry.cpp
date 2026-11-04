// B2 synthetic end-to-end board observation → DPT/2 encoder. No credentials.
#define PROBE_DEEP_ENABLED 1
#define PROBE_DEEP_AUTH_MODE 1
#define PROBE_DEEP_AUTH_ONLY 0
#define PROBE_A2_PIN_ED25519 1
#define PROBE_B2_LOOPBACK_TELEMETRY 1
#define PROBE_DEEP_USER "deep-unit-user"
#define PROBE_DEEP_PASSWORD "synthetic-unit-only"
#define PROBE_DEEP_EVERY_N_CYCLES 1
#include "../src/ssh_feasibility_main.cpp"
#include <cassert>
#include <cstring>
#include <iostream>
using namespace DenaProbe;
namespace {
bool contains(const Dpt::Message *m, const char *text) {
    return m && std::strstr(m->body, text) != nullptr;
}
Dpt::Message encode(Result r) {
    const Result safe = telemetrySafeResult(r);
    Dpt::Journal journal;
    assert(journal.begin("dp-test-01", "0123456789abcdef0123456789abcdef",
                         1, 100, true, 2));
    assert(journal.pushSsh(safe, 1000, true, nullptr, 0, 900, 990));
    const auto *item = journal.at(1);
    assert(item && item->length <= Dpt::kMaxBody);
    return *item;
}
}
int main() {
    Fake::reset();
    Result result = runSshTransport();
    assert(result.code == Code::PASS && result.deep.authCode == 1);
    assert(result.deep.code == 1 && result.deep.routeKind == 1);
    assert(Fake::authBeforeForward && Fake::forwardToApprovedLoopback);
    const auto m = encode(result);
    assert(contains(&m, "\"z\":{\"u\":990,\"s\":1"));
    assert(contains(&m, "\"rt\":1"));
    assert(contains(&m, "\"f\":{\"s\":1,\"r\":16384,\"n\":16384"));
    assert(contains(&m, "\"g\":{\"s\":1,\"r\":16384,\"n\":16384"));
    assert(!contains(&m, PROBE_DEEP_PASSWORD));
    Fake::reset();
    Fake::channelOpenRc = SSH_ERROR;
    result = runSshTransport();
    assert(result.deep.code == 30 && result.deep.routeKind == 1);
    const auto failed = encode(result);
    assert(contains(&failed, "\"rt\":1"));
    assert(contains(&failed, "\"s\":30"));
    assert(!contains(&failed, "\"g\":"));
    Fake::reset();
    Fake::authRc = SSH_AUTH_DENIED;
    result = runSshTransport();
    assert(result.deep.authCode == 10 && Fake::channelOpens == 0);
    const auto authFailed = encode(result);
    assert(contains(&authFailed, "\"rt\":1"));
    assert(!contains(&authFailed, "\"f\":"));
    Fake::reset();
    Fake::badPin = true;
    result = runSshTransport();
    assert(result.code == Code::HOST_KEY_MISMATCH);
    assert(Fake::authCalls == 0 && Fake::channelOpens == 0);
    std::cout << "PASS B2 route-tagged signed loopback success/fail/auth-denied/host-key\n";
}

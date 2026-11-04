// DenaProbe Lite: SSH password + two small controlled public data samples.
// This is a synthetic libssh test, not a live NPV egress test.
#define PROBE_B3_LITE 1
#define PROBE_DEEP_ENABLED 1
#define PROBE_DEEP_AUTH_MODE 1
#define PROBE_DEEP_AUTH_ONLY 0
#define PROBE_A2_PIN_ED25519 1
#define PROBE_DEEP_USER "deep-unit-user"
#define PROBE_DEEP_PASSWORD "synthetic-unit-only"
#define PROBE_DEEP_REMOTE_HOST "witness.example"
#define PROBE_DEEP_REMOTE_PORT 18180
#define PROBE_LITE_SAMPLE_BYTES 8192UL
#define PROBE_LITE_DWELL_MS 5000UL
#define PROBE_LITE_EVERY_N_CYCLES 1
#include "../src/ssh_feasibility_main.cpp"
#include <cassert>
#include <cstring>
#include <iostream>
using namespace DenaProbe;

namespace {
bool logged(const char *part) {
    for (const auto &line : Fake::logs)
        if (line.find(part) != std::string::npos) return true;
    return false;
}
Dpt::Message message(const Result &result) {
    Dpt::Journal journal;
    assert(journal.begin("dp-test-01", "0123456789abcdef0123456789abcdef",
                         1, 100, true, 2));
    const Result safe = telemetrySafeResult(result);
    assert(journal.pushSsh(safe, 1000, true, nullptr, 0, 900, 995, 990));
    const Dpt::Message *m = journal.at(1);
    assert(m && m->length <= Dpt::kMaxBody);
    return *m;
}
bool has(const Dpt::Message &m, const char *str) {
    return std::strstr(m.body, str) != nullptr;
}
}
int main() {
    Fake::reset();
    assert(authSettingsValid() && deepSettingsValid());
    const Result good = runSshTransport();
    assert(good.code == Code::PASS && good.tcp.code == 1);
    assert(good.auth.measured && good.auth.code == 1);
    assert(good.deep.measured && good.deep.code == 1 && good.deep.routeKind == 2);
    assert(good.deep.first.requested == 8192 && good.deep.first.received == 8192);
    assert(good.deep.second.requested == 8192 && good.deep.second.received == 8192);
    assert(good.deep.sessionMs >= 5000);
    assert(Fake::authCalls == 1 && Fake::channelOpens == 2);
    assert(Fake::forwardToLiteTarget && !Fake::forwardToApprovedLoopback);
    assert(Fake::authBeforeForward && Fake::hostKeyEd25519Requested);
    assert(logged("[deep] AUTH | mode=PASSWORD | outcome=AUTH_SUCCESS"));
    assert(logged("TRANSFER_2 | attempted=1 | channel_open=1"));
    const Dpt::Message wire = message(good);
    assert(has(wire, "\"c\":{"));
#if defined(PROBE_B3_LITE_WIRE) && PROBE_B3_LITE_WIRE
    assert(has(wire, "\"z\":{\"u\":995,\"s\":1"));
    assert(has(wire, "\"rt\":2"));
    assert(has(wire, "\"f\":{\"s\":1,\"r\":8192,\"n\":8192"));
    assert(has(wire, "\"g\":{\"s\":1,\"r\":8192,\"n\":8192"));
    assert(has(wire, "\"j\":{\"u\":990,\"s\":1"));
#else
    assert(!has(wire, "\"z\":"));
    assert(!has(wire, "\"j\":"));
#endif
    assert(!has(wire, PROBE_DEEP_PASSWORD));
    assert(!has(wire, PROBE_DEEP_USER));

    Fake::reset();
    Fake::authRc = SSH_AUTH_DENIED;
    Result r = runSshTransport();
    assert(r.code == Code::PASS && r.auth.code == 10 && r.deep.code == 10);
    assert(Fake::channelOpens == 0);

    Fake::reset();
    Fake::badPin = true;
    r = runSshTransport();
    assert(r.code == Code::HOST_KEY_MISMATCH && !r.auth.measured);
    assert(Fake::authCalls == 0 && Fake::channelOpens == 0);

    Fake::reset();
    Fake::authAgain = 1000;
    r = runSshTransport();
    assert(r.auth.code == 11 && r.deep.code == 11);
    assert(Fake::channelOpens == 0);

    Fake::reset();
    Fake::channelOpenRc = SSH_ERROR;
    r = runSshTransport();
    assert(r.auth.code == 1 && r.deep.code == 30);
    assert(r.deep.first.code == 23 && !r.deep.first.channelOpened);

    Fake::reset();
    Fake::secondSilent = true;
    r = runSshTransport();
    assert(r.auth.code == 1 && r.deep.code == 40);
    assert(r.deep.first.code == 1 && r.deep.second.code == 20);

    Fake::reset();
    Fake::wrongBody = true;
    r = runSshTransport();
    assert(r.auth.code == 1 && r.deep.code == 41);

    Fake::reset();
    Fake::dropAt = 100;
    r = runSshTransport();
    assert(r.deep.code == 90 && r.auth.code == 90);
    assert(r.wifiRssiDbm == 0);

    std::cout << "PASS Lite MCI Edge login, controlled 8KiB x2 transfer, "
              << "auth failures, no secret, wire=" << PROBE_B3_LITE_WIRE << "\n";
}

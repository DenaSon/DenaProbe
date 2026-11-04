// B1 controlled two-channel witness with synthetic SSH and a 0x5A body.
// Never connects to a real SSH host or includes live credentials.
#define PROBE_DEEP_ENABLED 1
#define PROBE_DEEP_AUTH_MODE 1
#define PROBE_DEEP_AUTH_ONLY 0
#define PROBE_A2_PIN_ED25519 1
#define PROBE_B1_FORWARDING_PILOT 1
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
unsigned cases = 0;
template <typename F> void verify(const char *name, F fn) {
    Fake::reset();
    fn();
    ++cases;
    std::cout << "PASS B1 " << name << "\n";
}
Result probe() {
    auto r = runSshTransport();
    assert(r.code == Code::PASS);
    assert(r.deep.measured && Fake::hostKeyEd25519Requested);
    return r;
}
}
int main() {
    verify("two complete bounded bodies and approved loopback only", [] {
        const Result r = probe();
        assert(r.deep.authCode == 1 && r.deep.code == 1);
        assert(r.deep.first.code == 1 && r.deep.second.code == 1);
        assert(r.deep.first.received == 16384 && r.deep.second.received == 16384);
        assert(r.deep.sessionMs >= 20000 && Fake::channelOpens == 2);
        assert(Fake::forwardToApprovedLoopback && Fake::authBeforeForward);
        assert(Fake::hostKeyOptionsBeforeConnect);
    });
    verify("signed DPT2 z+f+g for full witness, with no secret", [] {
        const Result r = probe();
        Dpt::Journal journal;
        assert(journal.begin("dp-test-01", "0123456789abcdef0123456789abcdef",
                             1, 100, true, 2));
        assert(journal.pushSsh(r, 1000, true, nullptr, 0, 900, 990));
        const auto *m = journal.at(1);
        assert(m && m->length <= Dpt::kMaxBody);
        assert(std::strstr(m->body, "\"z\":{\"u\":990,\"s\":1") != nullptr);
        assert(std::strstr(m->body, "\"f\":{\"s\":1,\"r\":16384,\"n\":16384") != nullptr);
        assert(std::strstr(m->body, "\"g\":{\"s\":1,\"r\":16384,\"n\":16384") != nullptr);
        assert(std::strstr(m->body, PROBE_DEEP_PASSWORD) == nullptr);
    });
    verify("B1 serial-only Deep mask preserves preauth DPT2 without z/f/g", [] {
        const Result measured = probe();
        const Result safe = telemetrySafeResult(measured);
        assert(measured.deep.code == 1 && safe.code == Code::PASS);
        assert(!safe.deep.measured && safe.tcp.measured);
        Dpt::Journal journal;
        assert(journal.begin("dp-test-01", "0123456789abcdef0123456789abcdef",
                             1, 100, true, 2));
        assert(journal.pushSsh(safe, 1000, true, nullptr, 0, 900, 990));
        const auto *m = journal.at(1);
        assert(m && std::strstr(m->body, "\"c\":") != nullptr);
        assert(std::strstr(m->body, "\"z\":") == nullptr);
        assert(std::strstr(m->body, "\"f\":") == nullptr);
        assert(std::strstr(m->body, "\"g\":") == nullptr);
    });
    verify("no forwarding if host key mismatch", [] {
        Fake::badPin = true;
        const auto r = runSshTransport();
        assert(r.code == Code::HOST_KEY_MISMATCH && Fake::authCalls == 0);
        assert(Fake::channelOpens == 0);
    });
    verify("no forwarding after denied password", [] {
        Fake::authRc = SSH_AUTH_DENIED;
        const auto r = probe();
        assert(r.deep.authCode == 10 && r.deep.code == 10);
        assert(Fake::channelOpens == 0);
    });
    verify("channel rejection is distinct from auth failure", [] {
        Fake::channelOpenRc = SSH_ERROR;
        const auto r = probe();
        assert(r.deep.authCode == 1 && r.deep.code == 30);
        assert(Fake::channelOpens == 1 && !r.deep.second.attempted);
    });
    verify("second sample stalls without false success", [] {
        Fake::secondSilent = true;
        const auto r = probe();
        assert(r.deep.first.code == 1 && r.deep.second.code == 20);
        assert(r.deep.code == 40 && Fake::channelOpens == 2);
    });
    verify("data integrity failure cannot pass", [] {
        Fake::wrongBody = true;
        const auto r = probe();
        assert(r.deep.authCode == 1 && r.deep.code == 41);
        assert(!r.deep.second.attempted);
    });
    verify("hotspot loss during dwell becomes local UNKNOWN", [] {
        Fake::dropAt = 5000;
        const auto r = probe();
        assert(r.deep.code == 90 && !r.deep.second.attempted);
    });
    std::cout << cases << " B1 controlled forwarding cases PASSED\n";
}

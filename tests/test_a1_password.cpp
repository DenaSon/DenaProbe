// A1 compiled against the real Deep and SshProbe code with synthetic libssh.
// NOT a live SSH test: no customer credentials, packets or targets are used.
#define PROBE_DEEP_ENABLED 1
#define PROBE_DEEP_AUTH_MODE 1
#define PROBE_DEEP_AUTH_ONLY 0 // Existing two-transfer regression intentionally opts in.
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
unsigned count = 0;
template <typename F> void check(const char *label, F f) {
    Fake::reset();
    f();
    ++count;
    std::cout << "PASS " << label << "\n";
}
bool logContains(const char *s) {
    for (const auto &line : Fake::logs)
        if (line.find(s) != std::string::npos) return true;
    return false;
}
Result observed() {
    const Result result = runSshTransport();
    assert(result.code == Code::PASS); // Pre-auth remains independent of Deep.
    assert(result.deep.measured);
    return result;
}
}
int main() {
    static_assert(PROBE_DEEP_ENABLED == 1 && PROBE_DEEP_AUTH_MODE == 1,
                  "Deep password source must compile in A1");
    check("A1 config validates password without requiring private key", [] {
        assert(deepSettingsValid());
        assert(std::strlen(PROBE_DEEP_PRIVATE_KEY_B64) == 0);
    });
    check("A1 bad host key never sends a password or service request", [] {
        Fake::badPin = true;
        const Result r = runSshTransport();
        assert(r.code == Code::HOST_KEY_MISMATCH && !r.deep.measured);
        assert(Fake::authCalls == 0 && Fake::serviceCalls == 0);
    });
    check("A1 password success retries AGAIN and transfers two bodies", [] {
        Fake::authAgain = 2;
        const Result r = observed();
        assert(Fake::userBeforeConnect);
        assert(Fake::authCalls == 3 && Fake::channelOpens == 2);
        assert(r.deep.authCode == 1 && r.deep.code == 1);
        assert(r.deep.first.requested == 16384 && r.deep.first.received == 16384);
        assert(r.deep.second.requested == 16384 && r.deep.second.received == 16384);
        assert(r.deep.sessionMs >= PROBE_DEEP_DWELL_MS);
        assert(logContains("[deep] AUTH | mode=PASSWORD | outcome=AUTH_SUCCESS"));
        assert(logContains("TRANSFER_1 | attempted=1 | channel_open=1"));
        assert(logContains("TRANSFER_2 | attempted=1 | channel_open=1"));
        assert(logContains("[deep] SUMMARY | auth=AUTH_SUCCESS"));
    });
    check("A1 rejected password never initiates forwarding or filtering verdict", [] {
        Fake::authRc = SSH_AUTH_DENIED;
        const Result r = observed();
        assert(r.deep.code == 10 && r.deep.authCode == 10);
        assert(Fake::authCalls == 1 && Fake::channelOpens == 0);
        assert(logContains("AUTH_REJECTED"));
        assert(!logContains("FILTERED"));
        ProbeState state{};
        state.validConfig = state.sshLastMeasured = state.deepLastMeasured = true;
        state.lastSshCode = Code::PASS;
        state.lastDeepCode = r.deep.code;
        assert(state.currentState(millis(), true).led == LedMode::UNKNOWN);
    });
    check("A1 partial auth never retries with unsupported fallback", [] {
        Fake::authRc = SSH_AUTH_PARTIAL;
        const Result r = observed();
        assert(r.deep.code == 10 && Fake::authCalls == 1 && Fake::channelOpens == 0);
    });
    check("A1 AUTH_AGAIN is bounded by absolute 8s deadline", [] {
        Fake::authAgain = 1000;
        const Result r = observed();
        assert(r.deep.authCode == 11 && r.deep.code == 11);
        assert(r.deep.authMs >= 8000 && r.deep.authMs < 8100);
        assert(Fake::channelOpens == 0);
    });
    check("A1 auth protocol error is not a data-plane failure", [] {
        Fake::authRc = SSH_ERROR;
        const Result r = observed();
        assert(r.deep.code == 12 && Fake::channelOpens == 0);
    });
    check("A1 hotspot loss during auth becomes LOCAL_UNMEASURABLE", [] {
        Fake::authAgain = 1000;
        Fake::dropAt = 100;
        const Result r = runSshTransport();
        assert(r.deep.measured && r.deep.code == 90);
        assert(Fake::channelOpens == 0);
    });
    check("A1 forwarding denied stays distinct from successful authentication", [] {
        Fake::channelOpenRc = SSH_ERROR;
        const Result r = observed();
        assert(r.deep.authCode == 1 && r.deep.code == 30);
        assert(!r.deep.first.channelOpened && !r.deep.second.attempted);
    });
    check("A1 stalled channel-open exits within five seconds", [] {
        Fake::channelAgain = 1000;
        const Result r = observed();
        assert(r.deep.authCode == 1 && r.deep.code == 31);
        assert(r.deep.first.elapsedMs >= 5000);
    });
    check("A1 first success does not conceal second sample timeout", [] {
        Fake::secondSilent = true;
        const Result r = observed();
        assert(r.deep.first.code == 1 && r.deep.second.code == 20);
        assert(r.deep.code == 40 && r.deep.second.received == 0);
    });
    check("A1 invalid body is not two-transfer success", [] {
        Fake::wrongBody = true;
        const Result r = observed();
        assert(r.deep.authCode == 1 && r.deep.code == 41);
        assert(r.deep.first.received == r.deep.first.requested);
        assert(!r.deep.second.attempted);
    });
    check("A1 session reset during dwell cannot appear healthy", [] {
        Fake::sessionDropAt = 5000;
        const Result r = observed();
        assert(r.deep.authCode == 1 && r.deep.code == 20);
        assert(r.deep.first.code == 1 && !r.deep.second.attempted);
    });
    check("A1 DPT2 contract never serializes an SSH password", [] {
        Fake::authRc = SSH_AUTH_DENIED;
        Result r = observed();
        Dpt::Journal journal;
        assert(journal.begin("dp-test-01", "0123456789abcdef0123456789abcdef",
                             1, 100, true, 2));
        assert(journal.pushSsh(r, 1000, true, nullptr, 0, 900, 990));
        const auto *m = journal.at(1);
        assert(m && std::strstr(m->body, "\"z\":{\"u\":990,\"s\":10") != nullptr);
        assert(std::strstr(m->body, PROBE_DEEP_PASSWORD) == nullptr);
        assert(std::strstr(m->body, "\"f\":") == nullptr);
        assert(m->length <= Dpt::kMaxBody);
    });
    std::cout << count << " A1 password-auth simulated host cases passed\n";
}

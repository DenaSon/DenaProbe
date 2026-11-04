// A2 safe pilot: test real implementation with synthetic libssh.
// No SSH forwarding must be attempted after a successful authentication.
#define PROBE_DEEP_ENABLED 1
#define PROBE_DEEP_AUTH_MODE 1
#define PROBE_DEEP_AUTH_ONLY 1
#define PROBE_A2_PIN_ED25519 1
#define PROBE_DEEP_USER "deep-unit-user"
#define PROBE_DEEP_PASSWORD "synthetic-unit-only"
#define PROBE_DEEP_EVERY_N_CYCLES 1
#include "../src/ssh_feasibility_main.cpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>

using namespace DenaProbe;
static bool logged(const char *part) {
    for (const auto &line : Fake::logs) {
        if (line.find(part) != std::string::npos) return true;
    }
    return false;
}
int main() {
    Fake::reset();
    assert(deepSettingsValid());
    Result r = runSshTransport();
    assert(r.code == Code::PASS && r.deep.measured);
    assert(r.deep.authCode == 1 && r.deep.code == 90);
    assert(r.deep.first.attempted == false && r.deep.second.attempted == false);
    assert(Fake::authCalls == 1 && Fake::channelOpens == 0);
    assert(Fake::hostKeyEd25519Requested && Fake::hostKeyOptionsBeforeConnect);
    assert(logged("outcome=AUTH_SUCCESS"));
    assert(logged("CHANNEL | outcome=NOT_TESTED | reason=AUTH_ONLY"));
    assert(logged("TRANSFER_1 | outcome=NOT_TESTED"));
    assert(logged("filtering_verdict=INCONCLUSIVE"));
    Dpt::Journal journal;
    assert(journal.begin("dp-test-01", "0123456789abcdef0123456789abcdef",
                         1, 100, true, 2));
    assert(journal.pushSsh(r, 1000, true, nullptr, 0, 900, 990));
    const auto *m = journal.at(1);
    assert(m && std::strstr(m->body, "\"z\":{\"u\":990,\"s\":90") != nullptr);
    assert(std::strstr(m->body, "\"f\":") == nullptr);
    assert(std::strstr(m->body, "\"g\":") == nullptr);
    assert(std::strstr(m->body, PROBE_DEEP_PASSWORD) == nullptr);
    Fake::reset();
    Fake::authRc = SSH_AUTH_DENIED;
    r = runSshTransport();
    assert(r.code == Code::PASS && r.deep.authCode == 10 && r.deep.code == 10);
    assert(Fake::channelOpens == 0);
    assert(Fake::hostKeyEd25519Requested && Fake::hostKeyOptionsBeforeConnect);
    Fake::reset();
    Fake::badPin = true;
    r = runSshTransport();
    assert(r.code == Code::HOST_KEY_MISMATCH);
    assert(Fake::authCalls == 0 && Fake::channelOpens == 0);
    assert(Fake::hostKeyEd25519Requested && Fake::hostKeyOptionsBeforeConnect);
    std::cout << "PASS A2 auth-only success/reject/bad-key with no forwarding, DPT2 NOT_TESTED\n";
}

// Lite must still test verified SSH password login without a public responder.
#define PROBE_B3_LITE 1
#define PROBE_DEEP_ENABLED 1
#define PROBE_DEEP_AUTH_MODE 1
#define PROBE_DEEP_AUTH_ONLY 0
#define PROBE_A2_PIN_ED25519 1
#define PROBE_DEEP_USER "deep-unit-user"
#define PROBE_DEEP_PASSWORD "synthetic-unit-only"
#define PROBE_DEEP_REMOTE_HOST "127.0.0.1"
#define PROBE_DEEP_REMOTE_PORT 18180
#define PROBE_LITE_EVERY_N_CYCLES 1
#include "../src/ssh_feasibility_main.cpp"
#include <cassert>
#include <iostream>
using namespace DenaProbe;
int main() {
    Fake::reset();
    assert(authSettingsValid() && !deepSettingsValid());
    const Result r = runSshTransport();
    assert(r.code == Code::PASS && r.auth.measured && r.auth.code == 1);
    assert(r.deep.measured && r.deep.code == 90 && r.deep.routeKind == 3);
    assert(Fake::authCalls == 1 && Fake::channelOpens == 0);
    assert(Fake::hostKeyEd25519Requested && Fake::userBeforeConnect);
    std::cout << "PASS Lite invalid HTTP target, auth-only fallback, zero forwards\n";
}

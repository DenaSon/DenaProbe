#include "../src/ssh_feasibility_main.cpp"
#include <iostream>

namespace {
unsigned tests = 0;
template <class Test> void check(const char *name, Test test) {
    Fake::reset(); test(); ++tests;
    std::cout << "PASS " << name << '\n';
}
void bodyTimeout(Fake::Response response, int length) {
    Fake::response = response; Fake::contentLength = length;
    const auto r = HttpsQuality::run();
    assert(r.status == HttpsQuality::Status::BODY_ERROR);
    assert(r.deadlineExceeded && Fake::stops == 1);
    assert(Fake::now >= 12000 && Fake::now < 13500);
}
void resetOrchestration() {
    scheduler = {}; probeState = {}; quality = {}; eventQueue.begin();
    workerRunning = workerRunHttps = false; workerStartMs = 0;
    wifiStatusInitialized = previousWifiConnected = false;
    probeState.validConfig = true;
}
}

int main() {
    check("HTTPS silent fixed-length body exits at deadline", [] {
        bodyTimeout(Fake::Response::SILENT_BODY, 65536);
    });
    check("HTTPS silent lengthless body exits without sink writes", [] {
        bodyTimeout(Fake::Response::SILENT_BODY, -1);
    });
    check("HTTPS slow drip cannot renew absolute body budget", [] {
        bodyTimeout(Fake::Response::DRIP_BODY, 65536);
    });
    check("HTTPS stalled chunk header exits", [] {
        bodyTimeout(Fake::Response::SILENT_CHUNK_HEADER, -1);
    });
    check("HTTPS silent headers exit", [] {
        Fake::response = Fake::Response::SILENT_HEADERS;
        const auto r = HttpsQuality::run();
        assert(r.status == HttpsQuality::Status::TLS_OR_CONNECT_FAIL);
        assert(r.deadlineExceeded && Fake::now >= 20000 && Fake::now < 20200);
    });
    check("HTTPS dripped header cannot renew absolute budget", [] {
        Fake::response = Fake::Response::DRIP_HEADERS;
        const auto r = HttpsQuality::run();
        assert(r.deadlineExceeded && Fake::now >= 20000 && Fake::now < 20200);
    });
    check("HTTPS success retains CA, hostname and one DNS lookup", [] {
        const auto r = HttpsQuality::run();
        assert(r.status == HttpsQuality::Status::PASS && r.bytes == 65536);
        assert(!r.deadlineExceeded && Fake::dnsCalls == 1 && Fake::connects == 1);
        assert(Fake::tlsHostname == HttpsQuality::kHost);
        assert(Fake::tlsRoot == HttpsQuality::kGtsRootR4);
    });
    check("HTTPS complete slow body remains a slow sample", [] {
        Fake::bodyDelay = 80;
        assert(HttpsQuality::run().status == HttpsQuality::Status::SLOW_64K_SAMPLE_SUSPECT);
    });
    check("HTTPS rejects oversize content length before body", [] {
        Fake::contentLength = 65537;
        assert(HttpsQuality::run().status == HttpsQuality::Status::BODY_TOO_LARGE);
    });
    check("HTTPS short body cannot become PASS", [] {
        Fake::payloadSize = 64000;
        assert(HttpsQuality::run().status == HttpsQuality::Status::BODY_INCOMPLETE);
    });
    check("HTTPS TLS rejection never becomes a successful sample", [] {
        Fake::tlsConnect = false;
        assert(HttpsQuality::run().status == HttpsQuality::Status::TLS_OR_CONNECT_FAIL);
    });
    check("HTTPS Wi-Fi loss during DNS has local status", [] {
        Fake::dropOnDns = 1; Fake::edgeDns = false;
        assert(HttpsQuality::run().status == HttpsQuality::Status::WIFI_DOWN);
        assert(Fake::connects == 0);
    });
    check("HTTPS Wi-Fi loss during body has local status", [] {
        Fake::response = Fake::Response::SILENT_BODY; Fake::dropAt = 500;
        assert(HttpsQuality::run().status == HttpsQuality::Status::WIFI_DOWN);
        assert(Fake::now < 600 && Fake::stops == 1);
    });
    check("HTTPS deadline remains correct across millis wrap", [] {
        Fake::now = UINT32_MAX - 1000;
        Fake::response = Fake::Response::SILENT_BODY;
        const auto r = HttpsQuality::run();
        assert(r.deadlineExceeded && r.totalMs >= 12000 && r.totalMs < 13500);
    });
    check("SSH Wi-Fi loss on failed DNS skips independent control", [] {
        Fake::dropOnDns = 1; Fake::edgeDns = false;
        assert(runSshTransport().code == Code::WIFI_LOST);
        assert(Fake::dnsCalls == 1 && Fake::serviceCalls == 0);
    });
    check("SSH Wi-Fi loss on cached DNS success opens no session", [] {
        Fake::dropOnDns = 1;
        assert(runSshTransport().code == Code::WIFI_LOST);
        assert(Fake::serviceCalls == 0);
    });
    check("SSH Wi-Fi loss during DNS control is not DNS_FAIL", [] {
        Fake::edgeDns = false; Fake::dropOnDns = 2;
        assert(runSshTransport().code == Code::WIFI_LOST);
        assert(Fake::dnsCalls == 2);
    });
    check("SSH actual DNS failure preserves DNS_FAIL", [] {
        Fake::edgeDns = false;
        assert(runSshTransport().code == Code::DNS_FAIL);
        assert(Fake::dnsCalls == 2 && Fake::serviceCalls == 0);
    });
    check("SSH bad pin sends no service request", [] {
        Fake::badPin = true;
        assert(runSshTransport().code == Code::HOST_KEY_MISMATCH);
        assert(Fake::serviceCalls == 0);
    });
    check("SSH post-transport service timeout remains distinct", [] {
        Fake::serviceRc = SSH_AGAIN;
        const auto r = runSshTransport();
        assert(r.code == Code::SERVICE_ACCEPT_TIMEOUT && r.stages.transportVerified);
        assert(r.serviceMs >= 8000 && r.serviceMs < 8100);
    });
    check("SSH transport timeout never attempts service request", [] {
        Fake::transportRc = SSH_AGAIN;
        assert(runSshTransport().code == Code::SSH_CONNECT_TIMEOUT);
        assert(Fake::serviceCalls == 0 && Fake::now < 12100);
    });
    check("Scheduler preserves cadence and wraparound", [] {
        ProbeScheduler s;
        const uint32_t start = UINT32_MAX - 10000;
        assert(s.sshDue(start)); s.markSshStarted(start);
        assert(!s.sshDue(start + 29999) && s.sshDue(start + 30000));
        assert(s.claimHttpsIfDue(start, true));
        assert(!s.claimHttpsIfDue(start + 179999, true));
        assert(s.claimHttpsIfDue(start + 180000, true));
        s.retryHttpsNextProbe(); assert(!s.claimHttpsIfDue(start, false));
        assert(s.claimHttpsIfDue(start, true));
    });
    check("Independent state freshness and Wi-Fi priority", [] {
        ProbeState s; s.validConfig = s.sshLastMeasured = s.httpsLastMeasured = true;
        s.lastSshCode = Code::PASS; s.lastHttpsStatus = HttpsQuality::Status::PASS;
        assert(s.currentState(100, true).led == LedMode::SSH_READY);
        assert(s.currentState(90000, true).ssh == SshPathState::STALE);
        s.lastSshResultAtMs = 360000;
        assert(s.currentState(360000, true).https == PublicHttpsState::STALE);
        assert(s.currentState(360000, false).led == LedMode::WIFI_DOWN);
        s.lastSshCode = Code::WIFI_LOST;
        assert(s.currentState(360000, true).ssh == SshPathState::LOCAL_UNMEASURABLE);
    });
    check("Worker emits SSH first, finishes once and allows next probe after HTTPS timeout", [] {
        resetOrchestration(); workerRunHttps = workerRunning = true;
        Fake::response = Fake::Response::SILENT_BODY;
        probeWorker(nullptr);
        ProbeEvent e;
        assert(eventQueue.receive(e) && e.kind == ProbeEventKind::SSH_RESULT);
        assert(!e.workerFinished); consumeEvent(e);
        assert(workerRunning && workerStartMs == e.completedAtMs);
        assert(!probeState.httpsLastMeasured && quality.probeSequence == 1);
        assert(eventQueue.receive(e) && e.kind == ProbeEventKind::HTTPS_RESULT);
        assert(e.workerFinished && e.https.deadlineExceeded); consumeEvent(e);
        assert(!workerRunning && !probeState.stalled && quality.probeSequence == 1);
        assert(!eventQueue.receive(e) && Fake::taskDeletes == 1);
        Fake::now = 30000; loop();
        assert(workerRunning && Fake::taskCreates == 1);
    });
    check("Partial worker completion cannot overlap with another worker", [] {
        resetOrchestration(); Fake::now = 40000; workerRunning = true;
        ProbeEvent e; e.ssh.code = Code::PASS; e.completedAtMs = Fake::now;
        consumeEvent(e); loop();
        assert(workerRunning && Fake::taskCreates == 0 && !probeState.stalled);
    });
    check("Unexpected genuine stall remains latched without killing crypto", [] {
        resetOrchestration(); workerRunning = true; Fake::now = kTaskStalledMs;
        loop(); assert(probeState.stalled && Fake::taskDeletes == 0);
        workerRunning = false; Fake::now += 30000; loop();
        assert(Fake::taskCreates == 0);
    });
    std::cout << tests << " R1 host cases passed (simulated peripherals; hardware pending)\n";
}

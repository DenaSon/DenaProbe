#include "../src/ssh_feasibility_main.cpp"
#include "../src/denaprobe/TelemetryAck.h"
#include <iostream>
#include <initializer_list>
#include <string>

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
void addQualitySamples(QualityWindow &window, Code code, unsigned count) {
    Result sample{};
    sample.code = code;
    for (unsigned i = 0; i < count; ++i) window.recordAndPrint(sample);
}
void expectQualityTokens(std::initializer_list<const char *> tokens) {
    assert(!Fake::logs.empty());
    const std::string &line = Fake::logs.back();
    assert(line.find("[quality-window]") != std::string::npos);
    for (const char *token : tokens) {
        assert(line.find(token) != std::string::npos);
    }
}
bool hasLog(const char *needle) {
    for (const auto &entry : Fake::logs) {
        if (entry.find(needle) != std::string::npos) return true;
    }
    return false;
}
void resetOrchestration() {
    scheduler = {}; probeState = {}; clockDiagnostics = {};
    quality = {}; eventQueue.begin();
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
    check("LED holds solid for SSH pass when HTTPS is unknown or clock invalid", [] {
        ProbeState s;
        s.validConfig = s.sshLastMeasured = true;
        s.lastSshCode = Code::PASS; s.lastSshResultAtMs = 100;
        assert(s.currentState(100, true).led == LedMode::SSH_READY);
        s.httpsLastMeasured = true; s.lastHttpsResultAtMs = 100;
        s.lastHttpsStatus = HttpsQuality::Status::CLOCK_NOT_READY;
        assert(s.currentState(100, true).led == LedMode::SSH_READY);
        s.lastHttpsStatus = HttpsQuality::Status::LOW_MEMORY;
        assert(s.currentState(100, true).led == LedMode::SSH_READY);
        s.lastHttpsStatus = HttpsQuality::Status::PASS;
        assert(s.currentState(100, true).led == LedMode::SSH_READY);
        assert(s.currentState(kHttpsFreshnessMs + 100, true).https ==
               PublicHttpsState::STALE);
        // SSH is also stale by then; restore a fresh SSH result.
        s.lastSshResultAtMs = kHttpsFreshnessMs + 100;
        assert(s.currentState(kHttpsFreshnessMs + 100, true).led ==
               LedMode::SSH_READY);
    });
    check("LED prioritizes Wi-Fi, SSH failures and measured HTTPS warnings", [] {
        ProbeState s; s.validConfig = s.sshLastMeasured = s.httpsLastMeasured = true;
        s.lastSshCode = Code::PASS; s.lastSshResultAtMs = 100;
        s.lastHttpsResultAtMs = 100;
        s.lastHttpsStatus = HttpsQuality::Status::SLOW_64K_SAMPLE_SUSPECT;
        assert(s.currentState(100, true).led == LedMode::HTTPS_SLOW);
        s.lastHttpsStatus = HttpsQuality::Status::DNS_FAIL;
        assert(s.currentState(100, true).led == LedMode::HTTPS_FAILURE);
        assert(s.currentState(100, false).led == LedMode::WIFI_DOWN);
        s.lastSshCode = Code::SSH_CONNECT_TIMEOUT;
        assert(s.currentState(100, true).led == LedMode::SSH_FAILURE);
        s.lastSshCode = Code::WIFI_LOST;
        assert(s.currentState(100, true).led == LedMode::UNKNOWN);
        s.lastSshCode = Code::PASS; s.sshLastMeasured = false;
        assert(s.currentState(100, true).led == LedMode::UNKNOWN);
    });
    check("Onboard LED timing preserves solid and warning blink patterns", [] {
        StatusLed led; led.begin();
        led.setMode(LedMode::SSH_READY);
        Fake::now = 100; led.update(); assert(Fake::ledLevel == HIGH);
        Fake::now = 1600; led.update(); assert(Fake::ledLevel == HIGH);
        led.setMode(LedMode::WIFI_DOWN);
        Fake::now = 1500; led.update(); assert(Fake::ledLevel == LOW);
        Fake::now = 200; led.update(); assert(Fake::ledLevel == HIGH);
        led.setMode(LedMode::SSH_FAILURE);
        Fake::now = 200; led.update(); assert(Fake::ledLevel == LOW);
        Fake::now = 350; led.update(); assert(Fake::ledLevel == HIGH);
        led.setMode(LedMode::HTTPS_FAILURE);
        Fake::now = 800; led.update(); assert(Fake::ledLevel == LOW);
        Fake::now = 650; led.update(); assert(Fake::ledLevel == HIGH);
        led.setMode(LedMode::HTTPS_SLOW);
        Fake::now = 1200; led.update(); assert(Fake::ledLevel == HIGH);
        Fake::now = 1800; led.update(); assert(Fake::ledLevel == LOW);
    });
    check("SNTP waits for IPv4, logs both DNS controls and starts exactly once", [] {
        ClockDiagnostics clock;
        Fake::now = 10;
        clock.update(Fake::now, false, false, 0, false);
        clock.update(Fake::now, true, false, 0, false);
        clock.update(Fake::now, true, true, 0, true);
        assert(Fake::sntpConfigCalls == 0 && Fake::dnsCalls == 0);
        clock.update(Fake::now, true, true, 0, false);
        assert(Fake::sntpConfigCalls == 1 && Fake::dnsCalls == 2);
        assert(hasLog("sntp=STARTED | after_ipv4=1"));
        assert(hasLog("[clock-dns] host=time.cloudflare.com | result=PASS"));
        assert(hasLog("[clock-dns] host=pool.ntp.org | result=PASS"));
        assert(hasLog("epoch=0 | ready=NO"));
        assert(hasLog("udp123=UNVERIFIED"));
        clock.update(Fake::now + 500, true, true, 0, false);
        assert(Fake::sntpConfigCalls == 1 && Fake::dnsCalls == 2);
    });
    check("Clock reports waiting every ten seconds and recovery immediately", [] {
        ClockDiagnostics clock;
        clock.update(100, true, true, 0, false);
        const auto count = Fake::logs.size();
        clock.update(9999, true, true, 0, false);
        assert(Fake::logs.size() == count);
        clock.update(10200, true, true, 0, false);
        assert(Fake::logs.size() == count + 1);
        clock.update(10300, true, true, 1900000000, false);
        assert(Fake::logs.size() == count + 2);
        assert(hasLog("epoch=1900000000 | ready=YES"));
        assert(Fake::sntpConfigCalls == 1);
    });
    check("Clock returns to waiting after Wi-Fi loss and reinitializes once", [] {
        ClockDiagnostics clock;
        clock.update(100, true, true, 0, false);
        clock.update(200, false, false, 0, false);
        assert(hasLog("state=LINK_DOWN_OR_NO_IP"));
        clock.update(300, true, false, 0, false);
        assert(Fake::sntpConfigCalls == 1);
        clock.update(400, true, true, 0, false);
        assert(Fake::sntpConfigCalls == 2);
        assert(Fake::dnsCalls == 4);
    });
    check("Clock DNS failure remains a DNS observation, not UDP proof", [] {
        ClockDiagnostics clock;
        Fake::controlDns = false;
        clock.update(100, true, true, 0, false);
        assert(hasLog("[clock-dns] host=pool.ntp.org | result=FAIL"));
        assert(hasLog("udp123=NOT_TESTED"));
        assert(hasLog("epoch=0 | ready=NO"));
    });
    check("Wi-Fi loss is local, never SSH path failure or eligible sample", [] {
        QualityWindow window;
        addQualitySamples(window, Code::WIFI_LOST, 4);
        expectQualityTokens({"eligible=0 | pass=0 | network_failures=0",
                             "wifi_lost=4 | local_failures=4 | trust_failures=0",
                             "excluded=4", "ssh_latency_flag=COLLECTING"});
    });
    check("Mixed path failures and Wi-Fi losses have distinct counters", [] {
        QualityWindow window;
        addQualitySamples(window, Code::PASS, 4);
        addQualitySamples(window, Code::WIFI_LOST, 2);
        addQualitySamples(window, Code::DNS_FAIL, 1);
        addQualitySamples(window, Code::SERVICE_ACCEPT_TIMEOUT, 1);
        expectQualityTokens({"eligible=6 | pass=4 | network_failures=2",
                             "wifi_lost=2 | local_failures=2 | trust_failures=0",
                             "excluded=2", "ssh_latency_flag=PATH_FAILURES_OBSERVED"});
    });
    check("Host-key trust and resource failures cannot inflate path outages", [] {
        QualityWindow window;
        addQualitySamples(window, Code::PASS, 4);
        addQualitySamples(window, Code::HOST_KEY_MISMATCH, 1);
        addQualitySamples(window, Code::HOST_KEY_ERROR, 1);
        addQualitySamples(window, Code::SSH_OPTIONS_FAILED, 1);
        addQualitySamples(window, Code::SESSION_ALLOC_FAILED, 1);
        expectQualityTokens({"eligible=4 | pass=4 | network_failures=0",
                             "wifi_lost=0 | local_failures=2 | trust_failures=2",
                             "excluded=4", "ssh_latency_flag=BASELINE_NOT_CALIBRATED"});
    });
    check("Rolling window evicts old local losses without manufacturing failures", [] {
        QualityWindow window;
        addQualitySamples(window, Code::WIFI_LOST, kQualityWindowSamples);
        addQualitySamples(window, Code::PASS, 1);
        expectQualityTokens({"window=12/12 | eligible=1 | pass=1 | network_failures=0",
                             "wifi_lost=11 | local_failures=11 | trust_failures=0",
                             "excluded=11", "ssh_latency_flag=COLLECTING"});
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
    check("DPT/1 numeric registry SSH paths and milestones", [] {
        Result r{};
        r.code = Code::PASS;
        r.stages.bannerMs = 418; r.stages.kexInitTxMs = 424;
        r.stages.kexInitRxMs = 621; r.stages.algorithmsMs = 624;
        r.stages.newkeysRxMs = 2044; r.stages.transportVerified = true;
        assert(Dpt::code(r.code) == 1 && Dpt::stage(r) == 52);
        assert(Dpt::observations(r) == 255);
        r.code = Code::SERVICE_ACCEPT_TIMEOUT;
        assert(Dpt::code(r.code) == 50 && Dpt::stage(r) == 51);
        assert(Dpt::observations(r) == 127);
        r.code = Code::SSH_CONNECT_TIMEOUT; r.stages = {};
        assert(Dpt::code(r.code) == 30 && Dpt::stage(r) == 30);
        assert(Dpt::observations(r) == 0);
        r.code = Code::HOST_KEY_MISMATCH;
        assert(Dpt::code(r.code) == 41 && Dpt::stage(r) == 40);
        assert(Dpt::httpsCode(HttpsQuality::Status::SLOW_64K_SAMPLE_SUSPECT) == 2);
    });
    check("DPT/1 boot, seq and HTTPS subobject are immutable per event", [] {
        Dpt::Journal j;
        assert(j.begin("dp-lte-01", "57fce203c6e94baf8d32749c11f0a65d",
                       1, 100, false));
        assert(j.size() == 1 && j.at(0)->sequence == 1);
        assert(std::string(j.at(0)->body).find("\"k\":3") != std::string::npos);
        Result r{}; r.code = Code::PASS; r.wifiRssiDbm = -48;
        r.transportMs = 3320; r.serviceMs = 198; r.stages.startedAt = 160;
        r.stages.transportVerified = true;
        assert(j.pushSsh(r, 500, true));
        assert(j.at(1)->sequence == 2 && j.at(1)->kind == 1);
        assert(std::string(j.at(1)->body).find("\"h\":") == std::string::npos);
        HttpsQuality::Result h{};
        h.status = HttpsQuality::Status::SLOW_64K_SAMPLE_SUSPECT;
        h.bytes = 65536; h.bodyTransferMs = 4200; h.httpCode = 200;
        h.totalMs = 7700; h.headersMs = 3490; h.firstBodyMs = 3510;
        assert(j.pushSsh(r, 700, true, &h, 8700));
        assert(j.at(2)->sequence == 3 && j.at(2)->completedUptime == 8700);
        assert(std::string(j.at(2)->body).find("\"h\":{\"c\":2,\"u\":8700") != std::string::npos);
        assert(std::string(j.at(2)->body).find("\"n\":65536,\"bt\":4200") != std::string::npos);
        assert(j.at(2)->length == strlen(j.at(2)->body));
        assert(j.size() == 3 && j.choose() == 0); // BOOT first.
        j.remove(1);
        assert(j.choose() == 1); // Newest result when no urgent event.
    });
    check("DPT/1 queue bounded; pending BOOT cannot be evicted", [] {
        Dpt::Journal j;
        assert(j.begin("dp-lte-01", "57fce203c6e94baf8d32749c11f0a65d",
                       1, 12, true));
        Result r{}; r.code = Code::DNS_FAIL;
        for (int i = 0; i < 18; ++i) assert(j.pushSsh(r, 100 + i, true));
        assert(j.size() == Dpt::kQueueCapacity && j.dropped() == 7);
        assert(j.at(0)->kind == 3 && j.at(0)->sequence == 1);
        assert(j.choose() == 0);
    });
    check("DPT/1 uptime is monotonic across wrap and preserves completion", [] {
        Dpt::ExtendedUptime clock;
        clock.update(0xfffffff0U);
        clock.update(0x00000020U);
        assert(clock.now() == (1ULL << 32) + 0x20U);
        assert(clock.at(0xfffffff8U) == 0xfffffff8ULL);
        assert(clock.at(0x00000018U) == (1ULL << 32) + 0x18U);
    });
    check("DPT/1 ACK accepts permuted exact identity and history-only", [] {
        const char *boot = "57fce203c6e94baf8d32749c11f0a65d";
        const char *json = " { \"ack\" : {\"r\":2},\"q\":16,\"b\":\"57fce203c6e94baf8d32749c11f0a65d\",\"v\":1 } ";
        uint8_t ack = 255;
        Dpt::AckParser p(json);
        assert(p.matches(boot, 16, ack) && ack == 2);
    });
    check("DPT/1 ACK rejects stale/mismatched, duplicate and garbage fields", [] {
        const char *boot = "57fce203c6e94baf8d32749c11f0a65d";
        const char *bad[] = {
            "{\"v\":1,\"b\":\"57fce203c6e94baf8d32749c11f0a65d\",\"q\":17,\"ack\":{\"r\":0}}",
            "{\"v\":1,\"b\":\"57fce203c6e94baf8d32749c11f0a65e\",\"q\":16,\"ack\":{\"r\":0}}",
            "{\"v\":1,\"b\":\"57fce203c6e94baf8d32749c11f0a65d\",\"q\":16,\"ack\":{\"r\":3}}",
            "{\"v\":1,\"v\":1,\"b\":\"57fce203c6e94baf8d32749c11f0a65d\",\"q\":16,\"ack\":{\"r\":0}}",
            "{\"v\":1,\"b\":\"57fce203c6e94baf8d32749c11f0a65d\",\"q\":16,\"ack\":{\"r\":0,\"x\":2}}",
            "{\"v\":1,\"b\":\"57fce203c6e94baf8d32749c11f0a65d\",\"q\":016,\"ack\":{\"r\":0}}",
            "{\"v\":1,\"b\":\"57fce203c6e94baf8d32749c11f0a65d\",\"q\":16,\"ack\":{\"r\":0}} extra"
        };
        for (const char *json : bad) {
            uint8_t ack = 255;
            Dpt::AckParser p(json);
            assert(!p.matches(boot, 16, ack));
        }
    });
    std::cout << tests << " R1 + DPT/1 host cases passed (simulated peripherals; hardware pending)\n";
}

#pragma once
#include "Arduino.h"
using ssh_session = void *;
using ssh_key = void *;
using ssh_buffer = void *;
using ssh_channel = void *;
constexpr int SSH_OK = 0, SSH_ERROR = -1, SSH_AGAIN = -2, SSH_PACKET_NOT_USED = 0;
constexpr int SSH_AUTH_SUCCESS = 0, SSH_AUTH_DENIED = 1, SSH_AUTH_PARTIAL = 2;
constexpr int SSH_AUTH_AGAIN = 4;
constexpr int SSH_OPTIONS_HOST = 1, SSH_OPTIONS_PORT = 2, SSH_OPTIONS_TIMEOUT = 3, SSH_OPTIONS_USER = 4, SSH_OPTIONS_HOSTKEYS = 5;
constexpr int SSH_PUBLICKEY_HASH_SHA256 = 1;
inline void *ssh_new() { static int session; return &session; }
inline void ssh_free(void *) {}
inline int ssh_options_set(void *, int option, const void *value) {
    if (option == SSH_OPTIONS_HOSTKEYS) {
        Fake::hostKeyOptionsBeforeConnect = (Fake::connectCalls == 0);
        Fake::hostKeyEd25519Requested =
            (std::strcmp(static_cast<const char *>(value), "ssh-ed25519") == 0);
    }
    if (option == SSH_OPTIONS_USER && Fake::connectCalls == 0)
        Fake::userBeforeConnect = true;
    return SSH_OK;
}
inline void ssh_set_blocking(void *, int) {}
inline int ssh_connect(void *) {
    ++Fake::connectCalls; Fake::tick(5); return Fake::transportRc;
}
inline int ssh_get_server_publickey(void *session, ssh_key *key) { *key = session; return SSH_OK; }
inline int ssh_get_publickey_hash(ssh_key, int, unsigned char **hash, size_t *len) {
    static unsigned char digest[32]{};
    digest[0] = Fake::badPin ? 1 : 0; *hash = digest; *len = 32; return SSH_OK;
}
inline void ssh_key_free(ssh_key) {}
inline void ssh_clean_pubkey_hash(unsigned char **) {}
inline int ssh_service_request(void *, const char *) {
    ++Fake::serviceCalls; Fake::tick(5); return Fake::serviceRc;
}

inline int ssh_userauth_password(ssh_session, const char *user, const char *password) {
    assert(user && password);
    assert(std::strcmp(user, "deep-unit-user") == 0);
    assert(std::strcmp(password, "synthetic-unit-only") == 0);
    ++Fake::authCalls;
    Fake::tick(20);
    if (Fake::authCalls <= Fake::authAgain) return SSH_AUTH_AGAIN;
    return Fake::authRc;
}
inline int ssh_pki_import_privkey_base64(const char *, const char *, void *, void *, ssh_key *key) {
    *key = nullptr; return SSH_ERROR;
}
inline int ssh_userauth_publickey(ssh_session, const char *, ssh_key) { return SSH_AUTH_DENIED; }
inline ssh_channel ssh_channel_new(ssh_session) {
    static int channel;
    return Fake::channelAlloc ? &channel : nullptr;
}
inline int ssh_channel_open_forward(ssh_channel, const char *host, int port, const char *, int) {
    Fake::forwardToApprovedLoopback &= (std::strcmp(host, "127.0.0.1") == 0 && port == 18180);
    Fake::forwardToLiteTarget &= (std::strcmp(host, "speedtest.tele2.net") == 0 && port == 80);
    Fake::authBeforeForward &= (Fake::authCalls > 0 && Fake::authRc == SSH_AUTH_SUCCESS);
    ++Fake::channelOpens;
    Fake::tick(5);
    if (Fake::channelOpens <= Fake::channelAgain) return SSH_AGAIN;
#if defined(PROBE_B3_LITE) && PROBE_B3_LITE
    if (Fake::channelOpenRc == SSH_OK) {
        Fake::forwardedHttpOffset = 0;
        Fake::forwardedHttpRequest.clear();
        const char *status = Fake::httpCode == 206 ? "206 Partial Content" :
                             Fake::httpCode == 302 ? "302 Found" : "200 OK";
        Fake::forwardedHttpResponse = std::string("HTTP/1.1 ") + status +
            "\r\nContent-Length: 8192\r\nConnection: close\r\n\r\n";
        Fake::forwardedHttpResponse.append(Fake::shortBody ? 512 : 8192, 'A');
    }
#endif
    return Fake::channelOpenRc;
}
inline int ssh_channel_write(ssh_channel, const void *buffer, uint32_t count) {
    Fake::tick(2);
    if (Fake::httpWriteError) return SSH_ERROR;
    const uint32_t actual = Fake::httpPartialWrite ? std::min(count, 7U) : count;
    Fake::forwardedHttpRequest.append(static_cast<const char *>(buffer), actual);
    return static_cast<int>(actual);
}
inline int ssh_channel_read_timeout(ssh_channel, void *buffer, uint32_t count, int, int) {
    Fake::tick(10);
    if (Fake::channelReadError) return SSH_ERROR;
    if (Fake::secondSilent && Fake::channelOpens >= 2) return SSH_AGAIN;
#if defined(PROBE_B3_LITE) && PROBE_B3_LITE
    if (Fake::forwardedHttpOffset >= Fake::forwardedHttpResponse.size()) return 0;
    const size_t n = std::min(static_cast<size_t>(count),
        Fake::forwardedHttpResponse.size() - Fake::forwardedHttpOffset);
    std::memcpy(buffer, Fake::forwardedHttpResponse.data() +
        Fake::forwardedHttpOffset, n);
    Fake::forwardedHttpOffset += n;
    return static_cast<int>(n);
#else
    if (Fake::shortBody && Fake::channelBytes >= 512) return 0;
    std::memset(buffer, Fake::wrongBody ? 0x00 : 0x5A, count);
    Fake::channelBytes += count;
    return static_cast<int>(count);
#endif
}
inline int ssh_channel_is_eof(ssh_channel) {
#if defined(PROBE_B3_LITE) && PROBE_B3_LITE
    return Fake::forwardedHttpOffset >= Fake::forwardedHttpResponse.size();
#else
    return Fake::shortBody && Fake::channelBytes >= 512;
#endif
}
inline int ssh_channel_close(ssh_channel) { return SSH_OK; }
inline void ssh_channel_free(ssh_channel) {}
inline int ssh_is_connected(ssh_session) { return Fake::sessionConnected ? 1 : 0; }

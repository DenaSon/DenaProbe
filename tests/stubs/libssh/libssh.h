#pragma once
#include "Arduino.h"
using ssh_session = void *;
using ssh_key = void *;
using ssh_buffer = void *;
constexpr int SSH_OK = 0, SSH_AGAIN = -2, SSH_PACKET_NOT_USED = 0;
constexpr int SSH_OPTIONS_HOST = 1, SSH_OPTIONS_PORT = 2, SSH_OPTIONS_TIMEOUT = 3;
constexpr int SSH_PUBLICKEY_HASH_SHA256 = 1;
inline void *ssh_new() { static int session; return &session; }
inline void ssh_free(void *) {}
inline int ssh_options_set(void *, int, const void *) { return SSH_OK; }
inline void ssh_set_blocking(void *, int) {}
inline int ssh_connect(void *) { Fake::tick(5); return Fake::transportRc; }
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

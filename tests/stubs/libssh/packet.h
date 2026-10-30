#pragma once
#include "libssh.h"
using ssh_packet_callback = int (*)(ssh_session, uint8_t, ssh_buffer, void *);
struct ssh_packet_callbacks_struct { int start, n_callbacks; ssh_packet_callback *callbacks; void *user; };
inline void ssh_packet_set_callbacks(void *, ssh_packet_callbacks_struct *) {}

#pragma once
#include "libssh.h"
struct ssh_callbacks_struct { void *userdata; void (*connect_status_function)(void *, float); };
inline void ssh_callbacks_init(ssh_callbacks_struct *) {}
inline int ssh_set_callbacks(void *, ssh_callbacks_struct *) { return SSH_OK; }

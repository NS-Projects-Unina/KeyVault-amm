// system_context.c
#include "system_context.h"
#include <stddef.h>

static SystemContext global_sys_ctx = {NULL, -1};

void sys_ctx_set(SSL_CTX *ctx, int fd) {
    global_sys_ctx.server_ctx = ctx;
    global_sys_ctx.listen_fd = fd;
}

SystemContext* sys_ctx_get() {
    return &global_sys_ctx;
}
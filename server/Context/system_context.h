#ifndef SYSTEM_CONTEXT_H
#define SYSTEM_CONTEXT_H

#include <openssl/ssl.h>

// La struttura che mantiene il "motore" del server
typedef struct {
    SSL_CTX *server_ctx;
    int listen_fd;
} SystemContext;

// Funzioni per gestire questo stato globale
void sys_ctx_set(SSL_CTX *ctx, int fd);
SystemContext* sys_ctx_get();

#endif
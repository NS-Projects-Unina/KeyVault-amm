#include "service_connection.h"
#include "ssl_server.h"
#include "network.h"
#include "pki.h"
#include "system_context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int service_init_system() {
    setup_server_infrastructure();
    init_openssl();

    SSL_CTX *ctx = create_server_ctx("server_storage/certs/server.crt", 
                                     "server_storage/certs/server.key", 
                                     "server_storage/certs/ca.crt");
    if (ctx == NULL) {
        fprintf(stderr, "[-] ERRORE FATALE: Impossibile creare il contesto SSL.\n");
        exit(EXIT_FAILURE); 
    }
    int fd = create_tcp_socket();
    if (bind_socket(fd, 8080) < 0) return -1;
    listen_socket(fd, 128);

    sys_ctx_set(ctx, fd); 
    return 0;
}

void service_shutdown() {
    SystemContext *ctx = sys_ctx_get();
    if (ctx->server_ctx) { SSL_CTX_free(ctx->server_ctx); ctx->server_ctx = NULL; }
    if (ctx->listen_fd != -1) { close_socket(ctx->listen_fd); ctx->listen_fd = -1; }
    cleanup_openssl();
}

int service_accept_client(char *out_fp, size_t fp_len, char *out_user, size_t user_len, SSL **out_ssl){
    *out_ssl = NULL;
    SystemContext *sys = sys_ctx_get();
    
    int client_fd = accept_client(sys->listen_fd);
    if (client_fd < 0) return -1;
    
    SSL *ssl = accept_tls_connection(sys->server_ctx, client_fd); 
    if (!ssl) { close_socket(client_fd); return -1; }

    int res = get_client_full_identity(ssl, out_user, user_len, out_fp, fp_len);

    if (res == 1) printf("[+] Connessione mTLS stabilita (User: %s).\n", out_user);
    else if (res == 0) printf("[!] Connessione anonima (Fase Enrollment).\n");
    else { service_close_client(ssl); return -1; }

    *out_ssl = ssl;
    return res;
}

void service_close_client(SSL *ssl) {
    if (!ssl) return;
    int fd = SSL_get_fd(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    if (fd != -1) close_socket(fd);
}

int service_read_data(SSL *ssl, char *buffer, int max_len) {
    if (!ssl) return -1;
    return SSL_read(ssl, buffer, max_len);
}

int service_send_data(SSL *ssl, const char *data) {
    if (!ssl || !data) return -1;
    return SSL_write(ssl, data, strlen(data));
}
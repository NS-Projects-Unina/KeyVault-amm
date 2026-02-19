#include "service.h"
#include "ssl.h"
#include "network.h"
#include "pki.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

static SSL *active_ssl = NULL;
static int active_sockfd = -1;

// Funzione interna per recuperare in modo "invisibile" l'username di sistema
static const char* get_system_user() {
    struct passwd *pw = getpwuid(getuid());
    return (pw) ? pw->pw_name : "default_user";
}

int client_service_init_session() {
    const char *username = get_system_user();
    char cert_path[256], key_path[256];
    
    snprintf(cert_path, sizeof(cert_path), "certs/%s.crt", username);
    snprintf(key_path, sizeof(key_path), "certs/%s.key", username);

    // 1. Auto-provisioning PKI
    if (generate_client_certificate(username) < 0) {
        fprintf(stderr, "[-] Impossibile generare o trovare il certificato per %s.\n", username);
        return -1;
    }

    // 2. Setup OpenSSL e Contesto Client
    init_openssl();
    SSL_CTX *ctx = create_client_ctx(cert_path, key_path, "certs/ca.crt");
    if (!ctx) return -1;
    
    // 3. Rete e Handshake
    active_sockfd = create_tcp_socket();
    if (connect_to_server(active_sockfd, "127.0.0.1", 8080) < 0) {
        SSL_CTX_free(ctx);
        return -1;
    }

    active_ssl = connect_tls_to_server(ctx, active_sockfd);
    SSL_CTX_free(ctx); 

    return (active_ssl != NULL) ? 0 : -1;
}

void client_service_store_data(const char *service_name, const char *password) {
    if (!active_ssl) return;

    char command[1024];
    char response[1024];

    // Formattazione protocollo: STORE|servizio|password
    snprintf(command, sizeof(command), "STORE|%s|%s", service_name, password);

    printf("[*] Invio al server in corso...\n");
    if (SSL_write(active_ssl, command, strlen(command)) <= 0) {
        fprintf(stderr, "[-] Errore di comunicazione col server.\n");
        return;
    }

    memset(response, 0, sizeof(response));
    if (SSL_read(active_ssl, response, sizeof(response) - 1) > 0) {
        printf("[SERVER]: %s\n", response);
    }
}
void client_service_close_session() {
    if (active_ssl) {
        SSL_shutdown(active_ssl);
        SSL_free(active_ssl);
        active_ssl = NULL;
    }
    if (active_sockfd != -1) {
        close_socket(active_sockfd); 
        active_sockfd = -1;
    }
    cleanup_openssl();
    printf("[*] Sessione terminata e risorse liberate.\n");
}
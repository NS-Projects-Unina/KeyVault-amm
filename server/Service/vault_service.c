#include "vault_service.h"
#include "ssl.h"
#include "network.h"
#include "pki.h"
#include "dal.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/x509.h>

// Lo stato dell'infrastruttura di rete è blindato qui dentro
static SSL_CTX *server_ctx = NULL;
static int listen_fd = -1;

// Manteniamo traccia del client attualmente connesso
static SSL *current_client_ssl = NULL;

int vault_service_init_system() {
    setup_server_infrastructure();
    init_openssl();
    server_ctx = create_server_ctx("certs/server.crt", "certs/server.key", "certs/ca.crt");
    if (!server_ctx) return -1;

    listen_fd = create_tcp_socket();
    if (bind_socket(listen_fd, 8080) < 0) return -1;
    listen_socket(listen_fd, 5); //Backlog di 5 connessioni in attesa

    return 0;
}

int vault_service_accept_client(char *out_identity, size_t max_len) {
    int client_fd = accept_client(listen_fd);
    if (client_fd < 0) return -1;

    current_client_ssl = accept_tls_connection(server_ctx, client_fd);
    if (!current_client_ssl) {
        close_socket(client_fd);
        return -1;
    }

    // Estrazione Identità mTLS
    X509 *cert = SSL_get_peer_certificate(current_client_ssl);
    if (!cert) {
        vault_service_close_client();
        return -1;
    }

    X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, out_identity, max_len);
    X509_free(cert);
        
    return 0;
}

int vault_service_read_data(char *buffer, int max_len) {
    if (!current_client_ssl) return -1;
    return SSL_read(current_client_ssl, buffer, max_len);
}

int vault_service_send_data(const char *data) {
    if (!current_client_ssl || !data) return -1;
    return SSL_write(current_client_ssl, data, strlen(data));
}

int vault_service_save_credential(const char *user, const char *svc, const char *blob) {
    return dal_save_record(user, svc, blob);
}


void vault_service_close_client() {
    if (current_client_ssl) {
        int fd = SSL_get_fd(current_client_ssl);
        SSL_shutdown(current_client_ssl);
        SSL_free(current_client_ssl);
        if (fd != -1) close_socket(fd);
        current_client_ssl = NULL;
    }
}

void vault_service_shutdown() {
    if (server_ctx) SSL_CTX_free(server_ctx);
    if (listen_fd != -1) close_socket(listen_fd);
    cleanup_openssl();
}
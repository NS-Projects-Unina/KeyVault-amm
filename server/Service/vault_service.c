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


// Inizializzazione con il nuovo contesto Ibrido
int vault_service_init_system() {
    setup_server_infrastructure();
    init_openssl();
    // Usiamo la funzione aggiornata in ssl.c che permette l'accesso anonimo
    server_ctx = create_server_ctx("certs/server.crt", "certs/server.key", "certs/ca.crt");
    if (!server_ctx) return -1;

    listen_fd = create_tcp_socket();
    if (bind_socket(listen_fd, 8080) < 0) return -1;
    listen_socket(listen_fd, 5);
    return 0;
}

/*
 * Accetta un client e determina il tipo di connessione.
 * return 1 se mTLS (autenticato), 0 se TLS Semplice (anonimo), -1 errore.
 */
int vault_service_accept_client(char *out_identity, size_t max_len) {
    int client_fd = accept_client(listen_fd);
    if (client_fd < 0) return -1;

    current_client_ssl = accept_tls_connection(server_ctx, client_fd);
    if (!current_client_ssl) {
        close_socket(client_fd);
        return -1;
    }

    // Usiamo la utility in ssl.c per capire chi è il client
    int res = get_client_common_name(current_client_ssl, out_identity, max_len);
    return res; 
}

// --- LOGICA DI ENROLLMENT ---
int vault_service_process_enrollment(const char *user, const char *pass, const char *csr_content) {
    // 1. Validazione Password di Registrazione (Esempio Hardcoded)
    if (strcmp(pass, "Segreto2026") != 0) {
        vault_service_send_data("ERROR|Password di registrazione errata");
        return -1;
    }

    // 2. Salvataggio CSR su file temporaneo per OpenSSL
    char csr_path[256], cert_path[256];
    snprintf(csr_path, sizeof(csr_path), "certs/%s.csr", user);
    snprintf(cert_path, sizeof(cert_path), "certs/%s.crt", user);

    FILE *f = fopen(csr_path, "w");
    if (!f) return -1;
    fputs(csr_content, f);
    fclose(f);

    // 3. Firma della CSR tramite PKI (La ca.key è solo qui!)
    if (pki_sign_client_request(user) != 0) {
        vault_service_send_data("ERROR|Errore durante la firma del certificato");
        return -1;
    }

    // 4. Lettura del certificato generato e invio al client
    FILE *fc = fopen(cert_path, "r");
    if (!fc) return -1;
    char cert_buf[4096];
    size_t n = fread(cert_buf, 1, sizeof(cert_buf)-1, fc);
    cert_buf[n] = '\0';
    fclose(fc);

    return vault_service_send_data(cert_buf);
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

char* vault_service_get_all(const char *user) {
    return dal_get_records_by_user(user);
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
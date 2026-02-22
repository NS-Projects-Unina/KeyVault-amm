#include "client_enrollment.h"
#include "client_utils.h"
#include "ssl.h"
#include "network.h"
#include "pki.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

// Funzione interna per garantire l'esistenza della cartella certs
static void ensure_certs_dir() {
    struct stat st = {0};
    if (stat("certs", &st) == -1) {
        #ifdef _WIN32
            mkdir("certs");
        #else
            mkdir("certs", 0700); // Permessi restrittivi per sicurezza
        #endif
    }
}

int client_service_needs_enrollment() {
    char cert_path[256];
    snprintf(cert_path, sizeof(cert_path), "certs/%s.crt", get_system_user());
    // Se il file .crt non esiste, l'utente deve registrarsi
    return (access(cert_path, F_OK) == -1);
}

int client_service_request_enrollment(const char *user) {
    ensure_certs_dir(); // Sicurezza: crea la cartella se manca
    
    char response[1024], command[256];
    
    init_openssl();
    SSL_CTX *tmp_ctx = create_client_basic_ctx("certs/ca.crt");
    if (!tmp_ctx) return -1;

    int tmp_fd = create_tcp_socket();
    if (connect_to_server(tmp_fd, "127.0.0.1", 8080) < 0) {
        SSL_CTX_free(tmp_ctx);
        return -1;
    }

    SSL *tmp_ssl = connect_tls_to_server(tmp_ctx, tmp_fd);
    if (!tmp_ssl) {
        SSL_CTX_free(tmp_ctx);
        close(tmp_fd);
        return -1;
    }

    snprintf(command, sizeof(command), "REQUEST_ENROLL|%s", user);
    SSL_write(tmp_ssl, command, strlen(command));
    
    memset(response, 0, sizeof(response));
    SSL_read(tmp_ssl, response, sizeof(response)-1);
    
    // Pulizia
    SSL_shutdown(tmp_ssl);
    SSL_free(tmp_ssl);
    SSL_CTX_free(tmp_ctx);
    close(tmp_fd);

    return (strstr(response, "OK")) ? 0 : -1;
}

int client_service_perform_enrollment(const char *user, const char *otp) {
    ensure_certs_dir(); // Essenziale prima di generare file CSR/KEY

    char csr_path[256], cert_path[256], csr_buf[4096], response[8192];
    snprintf(csr_path, sizeof(csr_path), "certs/%s.csr", user);
    snprintf(cert_path, sizeof(cert_path), "certs/%s.crt", user);

    // 1. Generazione locale della coppia di chiavi e del CSR
    // Questa funzione scrive in certs/%s.key e certs/%s.csr
    if (pki_generate_csr(user) != 0) return -1;

    // 2. Caricamento del CSR per inviarlo al server
    if (load_file_to_buffer(csr_path, csr_buf, sizeof(csr_buf)) != 0) return -1;

    // 3. Connessione temporanea per l'invio dell'OTP e del CSR
    SSL_CTX *tmp_ctx = create_client_basic_ctx("certs/ca.crt");
    int tmp_fd = create_tcp_socket();
    if (connect_to_server(tmp_fd, "127.0.0.1", 8080) < 0) return -1;
    
    SSL *tmp_ssl = connect_tls_to_server(tmp_ctx, tmp_fd);
    if (!tmp_ssl) return -1;

    char *full_cmd = malloc(8192);
    snprintf(full_cmd, 8192, "ENROLL|%s|%s|%s", user, otp, csr_buf);
    SSL_write(tmp_ssl, full_cmd, strlen(full_cmd));
    free(full_cmd);

    // 4. Ricezione del certificato firmato dal server
    memset(response, 0, sizeof(response));
    int bytes = SSL_read(tmp_ssl, response, sizeof(response)-1);
    
    int success = -1;
    if (bytes > 0 && strstr(response, "BEGIN CERTIFICATE")) {
        // Salviamo il certificato finale
        save_buffer_to_file(cert_path, response);
        // Il CSR non serve più
        remove(csr_path);
        success = 0;
    }

    SSL_shutdown(tmp_ssl);
    SSL_free(tmp_ssl);
    SSL_CTX_free(tmp_ctx);
    close(tmp_fd);
    return success;
}
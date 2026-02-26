#include "client_enrollment.h"
#include "client_utils.h"
#include "client_context.h" 
#include "ssl_client.h"
#include "network.h"
#include "crypto_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int client_service_needs_enrollment() {
    char cert_path[256];
    const char *username = client_context_get_username();
    if(strlen(username) == 0) {
        client_context_set_username(get_system_user());
        username = client_context_get_username();
    }
    snprintf(cert_path, sizeof(cert_path), CLIENT_CERTS_DIR "%s.crt", username);
    return (access(cert_path, F_OK) == -1);
}

int client_service_request_enrollment(const char *user) {
    ensure_certs_dir();
    char ca_path[] = CLIENT_CERTS_DIR "ca.crt";
    if (access(ca_path, F_OK) == -1) return -1;

    init_openssl();
    SSL_CTX *tmp_ctx = create_client_basic_ctx(ca_path);
    if (!tmp_ctx) return -1;

    int tmp_fd = create_tcp_socket();
    if (connect_to_server(tmp_fd, client_context_get_server_ip(), client_context_get_server_port()) < 0) {
        SSL_CTX_free(tmp_ctx); return -1;
    }

    SSL *tmp_ssl = connect_tls_to_server(tmp_ctx, tmp_fd);
    if (!tmp_ssl) { SSL_CTX_free(tmp_ctx); close(tmp_fd); return -1; }

    char command[256], response[1024];
    snprintf(command, sizeof(command), "REQUEST_ENROLL|%s", user);
    SSL_write(tmp_ssl, command, strlen(command));
    
    memset(response, 0, sizeof(response));
    SSL_read(tmp_ssl, response, sizeof(response)-1);
    
    SSL_shutdown(tmp_ssl);
    SSL_free(tmp_ssl);
    SSL_CTX_free(tmp_ctx);
    close(tmp_fd);

    return (strstr(response, "OK")) ? 0 : -1;
}

// --- Funzioni per l'Orchestratore ---

int client_enrollment_generate_csr(const char *user) {
    ensure_certs_dir();
    return generate_pkey_csr(user);
}

int client_enrollment_send_and_save_cert(const char *user, const char *otp) {
    char csr_path[256], cert_path[256], csr_buf[4096];
    snprintf(csr_path, sizeof(csr_path), CLIENT_CERTS_DIR "%s.csr", user);
    snprintf(cert_path, sizeof(cert_path), CLIENT_CERTS_DIR "%s.crt", user);

    if (load_file_to_buffer(csr_path, csr_buf, sizeof(csr_buf)) != 0) return -1;

    SSL_CTX *tmp_ctx = create_client_basic_ctx(CLIENT_CERTS_DIR "ca.crt");
    int tmp_fd = create_tcp_socket();
    if (connect_to_server(tmp_fd, client_context_get_server_ip(), client_context_get_server_port()) < 0) {
        SSL_CTX_free(tmp_ctx); return -1;
    }
    
    SSL *tmp_ssl = connect_tls_to_server(tmp_ctx, tmp_fd);
    if (!tmp_ssl) return -1;

    char *full_cmd = malloc(8192);
    snprintf(full_cmd, 8192, "ENROLL|%s|%s|%s", user, otp, csr_buf);
    SSL_write(tmp_ssl, full_cmd, strlen(full_cmd));
    free(full_cmd);

    char response[8192];
    memset(response, 0, sizeof(response));
    int bytes = SSL_read(tmp_ssl, response, sizeof(response)-1);

    SSL_shutdown(tmp_ssl);
    SSL_free(tmp_ssl);
    SSL_CTX_free(tmp_ctx);
    close(tmp_fd);

    if (bytes > 0 && strstr(response, "BEGIN CERTIFICATE")) {
        return save_buffer_to_file(cert_path, response);
    }
    return -1;
}

void client_enrollment_cleanup_csr(const char *user) {
    char csr_path[256];
    snprintf(csr_path, sizeof(csr_path), CLIENT_CERTS_DIR "%s.csr", user);
    remove(csr_path);
}
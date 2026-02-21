#include "client_enrollment.h"
#include "client_utils.h"
#include "ssl.h"
#include "network.h"
#include "pki.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int client_service_needs_enrollment() {
    char cert_path[256];
    snprintf(cert_path, sizeof(cert_path), "certs/%s.crt", get_system_user());
    return (access(cert_path, F_OK) == -1);
}

int client_service_request_enrollment(const char *user) {
    char response[1024], command[256];
    
    init_openssl();
    SSL_CTX *tmp_ctx = create_client_basic_ctx("certs/ca.crt");
    int tmp_fd = create_tcp_socket();
    if (connect_to_server(tmp_fd, "127.0.0.1", 8080) < 0) return -1;
    SSL *tmp_ssl = connect_tls_to_server(tmp_ctx, tmp_fd);
    if (!tmp_ssl) return -1;

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

int client_service_perform_enrollment(const char *user, const char *otp) {
    char csr_path[256], cert_path[256], csr_buf[4096], response[8192];
    snprintf(csr_path, sizeof(csr_path), "certs/%s.csr", user);
    snprintf(cert_path, sizeof(cert_path), "certs/%s.crt", user);

    if (pki_generate_csr(user) != 0) return -1;
    if (load_file_to_buffer(csr_path, csr_buf, sizeof(csr_buf)) != 0) return -1;

    SSL_CTX *tmp_ctx = create_client_basic_ctx("certs/ca.crt");
    int tmp_fd = create_tcp_socket();
    if (connect_to_server(tmp_fd, "127.0.0.1", 8080) < 0) return -1;
    SSL *tmp_ssl = connect_tls_to_server(tmp_ctx, tmp_fd);
    if (!tmp_ssl) return -1;

    char *full_cmd = malloc(8192);
    snprintf(full_cmd, 8192, "ENROLL|%s|%s|%s", user, otp, csr_buf);
    SSL_write(tmp_ssl, full_cmd, strlen(full_cmd));
    free(full_cmd);

    memset(response, 0, sizeof(response));
    int bytes = SSL_read(tmp_ssl, response, sizeof(response)-1);
    
    int success = -1;
    if (bytes > 0 && strstr(response, "BEGIN CERTIFICATE")) {
        save_buffer_to_file(cert_path, response);
        remove(csr_path);
        success = 0;
    }

    SSL_shutdown(tmp_ssl);
    SSL_free(tmp_ssl);
    SSL_CTX_free(tmp_ctx);
    close(tmp_fd);
    return success;
}


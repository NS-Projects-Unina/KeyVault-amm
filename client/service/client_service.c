#include "client_service.h"
#include "client_utils.h"
#include "client_context.h"
#include "crypto_utils.h"
#include "ssl_client.h"
#include "network.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void client_service_set_server_config(const char *ip) { client_context_set_server_ip(ip); }
void client_service_set_default_username() { client_context_set_username(get_system_user()); }
const char* client_service_get_username() { return client_context_get_username(); }

int client_service_import_ca(const char *source_path) {
    char buffer[8192];
    ensure_certs_dir();
    if (load_file_to_buffer(source_path, buffer, sizeof(buffer)) != 0) return -1;
    return save_buffer_to_file(CLIENT_CERTS_DIR "ca.crt", buffer);
}

int client_service_unlock_with_password(const char *password) {
    unsigned char derived_key[32];
    if (crypto_derive_from_password(password, derived_key) == 0) {
        client_context_set_session_key(derived_key);
        return 0;
    }
    return -1;
}

int client_service_unlock_with_usb(const char *path) {
    unsigned char loaded_key[32];
    if (crypto_load_usb_key(path, loaded_key) == 0) {
        client_context_set_session_key(loaded_key);
        return 0;
    }
    return -1;
}

int client_service_generate_new_usb_key(const char *path) {
    if (crypto_generate_usb_key(path) == 0) return client_service_unlock_with_usb(path);
    return -1;
}

int client_service_init_session() {
    client_service_close_session();
    
    const char *username = client_context_get_username();
    char cert_path[256], key_path[256], ca_path[256];
    snprintf(cert_path, sizeof(cert_path), CLIENT_CERTS_DIR "%s.crt", username);
    snprintf(key_path, sizeof(key_path), CLIENT_CERTS_DIR "%s.key", username);
    snprintf(ca_path, sizeof(ca_path), CLIENT_CERTS_DIR "ca.crt");
    
    if (access(cert_path, F_OK) == -1) return -1;

    init_openssl();
    SSL_CTX *ctx = create_client_mtls_ctx(cert_path, key_path, ca_path);
    if (!ctx) return -1;
    
    int fd = create_tcp_socket();
    if (connect_to_server(fd, client_context_get_server_ip(), client_context_get_server_port()) < 0) {
        SSL_CTX_free(ctx); return -1;
    }

    SSL *ssl = connect_tls_to_server(ctx, fd);
    SSL_CTX_free(ctx); 
    if (!ssl) return -1;

    client_context_set_ssl(ssl);
    client_context_set_sockfd(fd);
    return 0;
}

void client_service_close_session() {
    SSL *ssl = client_context_get_ssl();
    int fd = client_context_get_sockfd();
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); client_context_set_ssl(NULL); }
    if (fd != -1) { close(fd); client_context_set_sockfd(-1); }
}

int client_service_store_data(const char *svc, const char *pass, char *out_server_resp, size_t resp_len) {
    SSL *ssl = client_context_get_ssl();
    if (!ssl || !client_context_is_crypto_ready()) return -1;

    unsigned char encrypted_blob[1024];
    int encrypted_len = crypto_encrypt((unsigned char*)pass, strlen(pass), client_context_get_session_key(), encrypted_blob);

    char hex_payload[2048];
    for (int i = 0; i < encrypted_len; i++) sprintf(hex_payload + (i * 2), "%02x", encrypted_blob[i]);

    char command[4096];
    snprintf(command, sizeof(command), "STORE|%s|%s", svc, hex_payload);
    
    if (SSL_write(ssl, command, strlen(command)) > 0) {
        memset(out_server_resp, 0, resp_len);
        return SSL_read(ssl, out_server_resp, resp_len - 1);
    }
    return -1;
}

void client_service_fetch_and_parse_vault(void (*data_handler)(const char *svc, const char *pass)) {
    SSL *ssl = client_context_get_ssl();
    if (!ssl || !client_context_is_crypto_ready() || !data_handler) return;

    char response[8192];
    char *command = "GET_ALL";
    SSL_write(ssl, command, strlen(command));
    
    memset(response, 0, sizeof(response));
    int bytes = SSL_read(ssl, response, sizeof(response) - 1);
    if (bytes <= 0) return;

    // Parsing e decifratura gestiti internamente
    char *saveptr1, *saveptr2;
    char *line = strtok_r(response, "\n", &saveptr1);
    while (line != NULL) {
        char *svc = strtok_r(line, "|", &saveptr2);
        char *hex_payload = strtok_r(NULL, "|", &saveptr2);

        if (svc && hex_payload) {
            int blob_len = strlen(hex_payload) / 2;
            unsigned char *ciphertext = malloc(blob_len);
            for (int i = 0; i < blob_len; i++) {
                sscanf(hex_payload + (i * 2), "%02x", (unsigned int *)&ciphertext[i]);
            }

            unsigned char decrypted_pass[256];
            int decrypted_len = crypto_decrypt(ciphertext, blob_len, client_context_get_session_key(), decrypted_pass);

            if (decrypted_len > 0) {
                decrypted_pass[decrypted_len] = '\0';
                data_handler(svc, (const char*)decrypted_pass);
            }
            free(ciphertext);
        }
        line = strtok_r(NULL, "\n", &saveptr1);
    }
}
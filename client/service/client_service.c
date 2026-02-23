#include "client_service.h"
#include "client_utils.h"
#include "client_context.h"
#include "crypto_utils.h"
#include "ssl.h"
#include "network.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static SSL *active_ssl = NULL;
static int active_sockfd = -1;
static unsigned char session_key[AES_KEY_LEN];
static int is_crypto_ready = 0;

void client_service_set_server_config(const char *ip) {
    // Il Service riceve l'ordine dalla GUI e lo inoltra allo strato inferiore
    client_context_set_server_ip(ip);
}

// Inizializza la connessione mTLS
int client_service_init_session() {
    // 1. PULIZIA PREVENTIVA E RESET DELLO STATO
    if (active_ssl) {
        SSL_shutdown(active_ssl);
        SSL_free(active_ssl);
        active_ssl = NULL;
    }
    if (active_sockfd != -1) {
        close(active_sockfd);
        active_sockfd = -1;
    }

    const char *username = get_system_user();
    char cert_path[256], key_path[256];
    snprintf(cert_path, sizeof(cert_path), "certs/%s.crt", username);
    snprintf(key_path, sizeof(key_path), "certs/%s.key", username);

    // Se non abbiamo ancora i certificati, non possiamo inizializzare mTLS
    // Usciamo senza errore "fatale", l'enrollment gestirà il resto
    if (access(cert_path, F_OK) == -1) return -1;

    init_openssl();
    SSL_CTX *ctx = create_client_mtls_ctx(cert_path, key_path, "certs/ca.crt");
    if (!ctx) return -1;
    
    active_sockfd = create_tcp_socket();
    const char *ip = client_context_get_server_ip();
    int port = client_context_get_server_port();

    if (connect_to_server(active_sockfd, ip, port) < 0) {
        SSL_CTX_free(ctx);
        return -1;
    }

    active_ssl = connect_tls_to_server(ctx, active_sockfd);
    SSL_CTX_free(ctx); 

    return (active_ssl != NULL) ? 0 : -1;
}

// Imposta la chiave di sessione (chiamata dalla GUI o dal bootstrapper)
void client_service_set_session_key(const unsigned char *key) {
    memcpy(session_key, key, AES_KEY_LEN);
    is_crypto_ready = 1;
}

// STORE: Ora restituisce la risposta del server come stringa, senza stamparla
int client_service_store_data_encrypted(const char *svc, const char *pass, char *out_server_resp, size_t resp_len) {
    if (!active_ssl || !is_crypto_ready) return -1;

    unsigned char encrypted_blob[1024];
    int encrypted_len = crypto_encrypt((unsigned char*)pass, strlen(pass), session_key, encrypted_blob);

    char hex_payload[2048];
    for (int i = 0; i < encrypted_len; i++) {
        sprintf(hex_payload + (i * 2), "%02x", encrypted_blob[i]);
    }

    char command[4096];
    snprintf(command, sizeof(command), "STORE|%s|%s", svc, hex_payload);
    
    if (SSL_write(active_ssl, command, strlen(command)) > 0) {
        memset(out_server_resp, 0, resp_len);
        return SSL_read(active_ssl, out_server_resp, resp_len - 1);
    }
    return -1;
}

// FETCH: accetta un puntatore a funzione (callback)
void client_service_fetch_vault(void (*data_handler)(const char *svc, const char *pass)) {
    if (!active_ssl || !is_crypto_ready || !data_handler) return;

    char *command = "GET_ALL";
    char response[8192];

    SSL_write(active_ssl, command, strlen(command));
    memset(response, 0, sizeof(response));
    int bytes = SSL_read(active_ssl, response, sizeof(response) - 1);
    
    if (bytes <= 0) return;

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
            int decrypted_len = crypto_decrypt(ciphertext, blob_len, session_key, decrypted_pass);

            if (decrypted_len > 0) {
                decrypted_pass[decrypted_len] = '\0';
                // Passa i dati decifrati al gestore (GUI o CLI)
                data_handler(svc, (const char*)decrypted_pass); //Funzione passata dall'argomento
            }
            free(ciphertext);
        }
        line = strtok_r(NULL, "\n", &saveptr1);
    }
}

void client_service_close_session() {
    if (active_ssl) {
        SSL_shutdown(active_ssl);
        SSL_free(active_ssl);
        active_ssl = NULL;
    }
    if (active_sockfd != -1) {
        close(active_sockfd); 
        active_sockfd = -1;
    }
    cleanup_openssl();
}
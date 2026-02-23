#include "client_service.h"
#include "client_utils.h"
#include "client_context.h" // Obbligatorio per gestire lo stato
#include "crypto_utils.h"
#include "ssl_client.h"
#include "network.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void client_service_set_server_config(const char *ip) { 
    client_context_set_server_ip(ip);
}

void client_service_set_default_username() {
    const char *sys_user = get_system_user();
    client_context_set_username(sys_user);
}

//Sviluppi futuri
void client_service_set_username(const char *username) {
    client_context_set_username(username);
}
const char* client_service_get_username() {
    return client_context_get_username();
}


int client_service_init_session() {
    // 1. PULIZIA PREVENTIVA (Recupero stato vecchio dal Context)
    SSL *old_ssl = client_context_get_ssl();
    int old_fd = client_context_get_sockfd();
    
    if (old_ssl) { SSL_shutdown(old_ssl); SSL_free(old_ssl); client_context_set_ssl(NULL); }
    if (old_fd != -1) { close(old_fd); client_context_set_sockfd(-1); }


    const char *username = client_context_get_username();
  
    //Spostare in una funzione utils
    char cert_path[256], key_path[256], ca_path[256];
    snprintf(cert_path, sizeof(cert_path), CLIENT_CERTS_DIR "%s.crt", username);
    snprintf(key_path, sizeof(key_path), CLIENT_CERTS_DIR "%s.key", username);
    snprintf(ca_path, sizeof(ca_path), CLIENT_CERTS_DIR "ca.crt");
    if (access(cert_path, F_OK) == -1) return -1;


    init_openssl();
    SSL_CTX *ctx = create_client_mtls_ctx(cert_path, key_path, ca_path);
    if (!ctx) return -1;
    
    // 2. CONNESSIONE USANDO IL CONTEXT
    int fd = create_tcp_socket();
    const char *ip = client_context_get_server_ip();
    int port = client_context_get_server_port();

    if (connect_to_server(fd, ip, port) < 0) {
        SSL_CTX_free(ctx);
        return -1;
    }

    SSL *ssl = connect_tls_to_server(ctx, fd);
    SSL_CTX_free(ctx); 

    // 3. SALVATAGGIO NUOVO STATO NEL CONTEXT
    client_context_set_ssl(ssl);
    client_context_set_sockfd(fd);

    return (ssl != NULL) ? 0 : -1;
}

// Salvataggio della chiave nello strato di sicurezza del Context
void client_service_set_session_key(const unsigned char *key) {
    client_context_set_session_key(key);
}

int client_service_store_data_encrypted(const char *svc, const char *pass, char *out_server_resp, size_t resp_len) {
    // Controllo stato tramite Context
    SSL *ssl = client_context_get_ssl();
    if (!ssl || !client_context_is_crypto_ready()) return -1;

    unsigned char encrypted_blob[1024];
    // Recupero chiave dal Context per la cifratura
    int encrypted_len = crypto_encrypt((unsigned char*)pass, strlen(pass), client_context_get_session_key(), encrypted_blob);

    char hex_payload[2048];
    for (int i = 0; i < encrypted_len; i++) {
        sprintf(hex_payload + (i * 2), "%02x", encrypted_blob[i]);
    }

    char command[4096];
    snprintf(command, sizeof(command), "STORE|%s|%s", svc, hex_payload);
    
    if (SSL_write(ssl, command, strlen(command)) > 0) {
        memset(out_server_resp, 0, resp_len);
        return SSL_read(ssl, out_server_resp, resp_len - 1);
    }
    return -1;
}

void client_service_fetch_vault(void (*data_handler)(const char *svc, const char *pass)) {
    SSL *ssl = client_context_get_ssl();
    if (!ssl || !client_context_is_crypto_ready() || !data_handler) return;

    char *command = "GET_ALL";
    char response[8192];

    SSL_write(ssl, command, strlen(command));
    memset(response, 0, sizeof(response));
    int bytes = SSL_read(ssl, response, sizeof(response) - 1);
    
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
            // Decifratura usando la chiave del Context
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

void client_service_close_session() {
    SSL *ssl = client_context_get_ssl();
    int fd = client_context_get_sockfd();

    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        client_context_set_ssl(NULL);
    }
    if (fd != -1) {
        close(fd); 
        client_context_set_sockfd(-1);
    }
    cleanup_openssl();
}


//Forse da spostare in utils.
int client_service_has_ca() {
    // Il Service conosce il percorso perché usa le definizioni di pki.h
    return (access("client_storage/certs/ca.crt", F_OK) == 0);
}
/**
 * Importa il certificato CA da un percorso sorgente allo storage isolato del client.
 * Nasconde alla GUI i dettagli del buffer e della destinazione finale.
 * @return 0 in caso di successo, -1 in caso di errore.
 */
int client_service_import_ca(const char *source_path) {
    char buffer[8192]; // Buffer per il PEM del certificato

    // 1. Assicuriamoci che la struttura delle cartelle esista
    ensure_certs_dir();

    // 2. Leggiamo il file dalla sorgente (es. la chiavetta USB dell'admin)
    if (load_file_to_buffer(source_path, buffer, sizeof(buffer)) != 0) {
        fprintf(stderr, "[-] Service: Impossibile leggere il file sorgente %s\n", source_path);
        return -1;
    }

    // 3. Salviamolo nella destinazione protetta del client
    // Il percorso è ora cablato qui, invisibile alla GUI.
    if (save_buffer_to_file(CLIENT_CERTS_DIR "ca.crt", buffer) != 0) {
        fprintf(stderr, "[-] Service: Errore nel salvataggio locale della CA.\n");
        return -1;
    }

    printf("[+] Service: CA importata con successo in %s\n", CLIENT_CERTS_DIR);
    return 0;
}

int client_service_unlock_with_password(const char *password) {
    unsigned char derived_key[32];
    // PBKDF2: Trasforma la password in chiave robusta
    if (crypto_derive_from_password(password, derived_key) == 0) {
        client_context_set_session_key(derived_key);
        return 0;
    }
    return -1;
}

int client_service_unlock_with_usb(const char *path) {
    unsigned char loaded_key[32];
    // Lettura diretta dei 32 byte di entropia
    if (crypto_load_usb_key(path, loaded_key) == 0) {
        client_context_set_session_key(loaded_key);
        return 0;
    }
    return -1;
}

int client_service_generate_new_usb_key(const char *path) {
    // Chiama la crypto_utils (il service può farlo, la GUI no)
    if (crypto_generate_usb_key(path) == 0) {
        return client_service_unlock_with_usb(path); // La carica anche subito
    }
    return -1;
}
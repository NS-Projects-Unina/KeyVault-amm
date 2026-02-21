#include "client_service.h"
#include "client_utils.h"
#include "crypto_utils.h"
#include "ssl.h"
#include "network.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static SSL *active_ssl = NULL;
static int active_sockfd = -1;
// Variabile di sessione: la chiave rimane qui finché il programma è aperto
static unsigned char session_key[AES_KEY_LEN];
static int is_crypto_ready = 0;

int client_service_init_session() {
    const char *username = get_system_user();
    char cert_path[256], key_path[256];
    
    snprintf(cert_path, sizeof(cert_path), "certs/%s.crt", username);
    snprintf(key_path, sizeof(key_path), "certs/%s.key", username);

    init_openssl();
    SSL_CTX *ctx = create_client_mtls_ctx(cert_path, key_path, "certs/ca.crt");
    if (!ctx) return -1;
    
    active_sockfd = create_tcp_socket();
    if (connect_to_server(active_sockfd, "127.0.0.1", 8080) < 0) return -1;

    active_ssl = connect_tls_to_server(ctx, active_sockfd);
    SSL_CTX_free(ctx); 

    return (active_ssl != NULL) ? 0 : -1;
}
// AGGIORNATA: Non prende più 'key' come parametro, usa quella di sessione
void client_service_store_data_encrypted(const char *svc, const char *pass) {
    if (!active_ssl || !is_crypto_ready) {
        printf("[-] Errore: Sessione crittografica non inizializzata.\n");
        return;
    }

    unsigned char encrypted_blob[1024];
    // Usiamo session_key (la variabile static del file)
    int encrypted_len = crypto_encrypt((unsigned char*)pass, strlen(pass), session_key, encrypted_blob);

    char hex_payload[2048];
    for (int i = 0; i < encrypted_len; i++) {
        sprintf(hex_payload + (i * 2), "%02x", encrypted_blob[i]);
    }

    char command[4096];
    snprintf(command, sizeof(command), "STORE|%s|%s", svc, hex_payload);
    
    if (SSL_write(active_ssl, command, strlen(command)) > 0) {
        char resp[1024];
        memset(resp, 0, sizeof(resp));
        SSL_read(active_ssl, resp, sizeof(resp)-1);
        printf("[SERVER]: %s\n", resp);
    }
}

void client_service_fetch_data_encrypted() {
    if (!active_ssl || !is_crypto_ready) return;

    char *command = "GET_ALL";
    char response[8192];

    SSL_write(active_ssl, command, strlen(command));
    memset(response, 0, sizeof(response));
    int bytes = SSL_read(active_ssl, response, sizeof(response) - 1);
    
    if (bytes <= 0) return;

    printf("\n┌──────────────────────────────┬──────────────────────────────┐\n");
    printf("│ %-28s │ %-28s │\n", "SERVIZIO", "PASSWORD (DECIFRATA)");
    printf("├──────────────────────────────┼──────────────────────────────┤\n");

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
            // Usiamo session_key in modo coerente
            int decrypted_len = crypto_decrypt(ciphertext, blob_len, session_key, decrypted_pass);

            if (decrypted_len > 0) {
                decrypted_pass[decrypted_len] = '\0';
                printf("│ %-28s │ %-28s │\n", svc, decrypted_pass);
            } else {
                printf("│ %-28s │ [ERRORE DECIFRATURA]         │\n", svc);
            }
            free(ciphertext);
        }
        line = strtok_r(NULL, "\n", &saveptr1);
    }
    printf("└──────────────────────────────┴──────────────────────────────┘\n");
}

int client_service_bootstrap_crypto() {
    int choice;
    char usb_path[256], full_path[512];

    // PULIZIA: Reset della chiave prima di ogni nuova configurazione
    memset(session_key, 0, AES_KEY_LEN);
    is_crypto_ready = 0;

    printf("\n=== CONFIGURAZIONE SICUREZZA VAULT ===\n");
    printf("1. Sblocca con USB esistente\n");
    printf("2. Genera NUOVA chiave su USB\n");
    printf("3. Usa Master Password\n");
    printf("Scelta: ");
    if (scanf("%d", &choice) != 1) return -1;

    if (choice == 1 || choice == 2) {
        printf("Punto di mount USB: ");
        scanf("%255s", usb_path);
        snprintf(full_path, sizeof(full_path), "%s/vault.key", usb_path);

        if (choice == 2) {
            if (crypto_generate_usb_key(full_path) != 0) return -1;
            printf("[+] Nuova chiave generata.\n");
        }

        if (crypto_load_usb_key(full_path, session_key) != 0) return -1;
        printf("[+] Chiave hardware caricata.\n");
    } else if (choice == 3) {
        char master[128];
        printf("Master Password: ");
        scanf("%127s", master);
        crypto_derive_from_password(master, session_key);
        printf("[+] Chiave derivata da password.\n");
    } else {
        return -1;
    }

    is_crypto_ready = 1;
    return 0;
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



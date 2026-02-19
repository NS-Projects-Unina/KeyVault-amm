#include "network.h"
#include "ssl.h" // Aggiunto per le funzioni TLS
#include "pki.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("Starting client...\n");
    printf("=======================================\n");
    printf("    KEY-VAULT: mTLS CLIENT             \n");
    printf("=======================================\n");

    // 1. PKI - Generazione identità (Simulazione GUI)
    const char *username = "giuseppe";
    char cert_path[256], key_path[256];
    
    // Prepariamo i percorsi ai file generati
    snprintf(cert_path, sizeof(cert_path), "certs/%s.crt", username);
    snprintf(key_path, sizeof(key_path), "certs/%s.key", username);

    if (generate_client_certificate(username) < 0) {
        printf("\n[-] Errore durante la generazione della PKI Client.\n");
        return 1;
    }

    // 2. SSL - Inizializzazione Contesto
    init_openssl();
    // Il client carica il SUO certificato, la SUA chiave e la CA per verificare il server
    SSL_CTX *ctx = create_client_ctx(cert_path, key_path, "certs/ca.crt");
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return 1;
    }

    // 3. NETWORK - Connessione TCP (Livello 1)
    int client_socket_fd = create_tcp_socket(); 
    if (client_socket_fd < 0) {
        fprintf(stderr, "Failed to create client socket\n");
        return 1;
    }

    printf("Attempting to connect to server at 127.0.0.1:8080...\n");
    if (connect_to_server(client_socket_fd, "127.0.0.1", 8080) < 0) {
        fprintf(stderr, "Failed to connect to the server\n");
        close_socket(client_socket_fd);
        return 1;
    }
    printf("TCP Connection established. Starting TLS Handshake...\n");

    // 4. SSL - Handshake mTLS (Il "Ponte")
    // Qui il client invia il certificato di 'giuseppe' e verifica quello del server
    SSL *ssl = connect_tls_to_server(ctx, client_socket_fd);
    
    if (ssl) {
        printf("\n[!!!] CONNESSO AL VAULT IN MODO SICURO [!!!]\n");
        printf("Identità verificata come: %s\n\n", username);

        // --- Qui andrà il ciclo di comunicazione (Livello 3) ---
        // Esempio: SSL_write(ssl, "HELLO SERVER", 12);

        while(1) {
            // Ciclo di invio comandi/password
        }

        // Chiusura sicura
        SSL_shutdown(ssl);
        SSL_free(ssl);
    } else {
        fprintf(stderr, "[-] TLS Handshake failed. Server not trusted or Client cert rejected.\n");
    }

    // 5. CLEANUP
    close_socket(client_socket_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
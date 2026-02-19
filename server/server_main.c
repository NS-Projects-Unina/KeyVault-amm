#include "network.h"
#include "ssl.h" // Aggiunto per TLS
#include "pki.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("Starting server...\n");
    printf("=======================================\n");
    printf("    KEY-VAULT: mTLS SERVER             \n");
    printf("=======================================\n");

    // 1. PKI - Auto-provisioning
    setup_server_infrastructure();

    // 2. SSL - Inizializzazione Contesto (Prima della rete)
    init_openssl();
    // Carichiamo i certificati appena generati dalla PKI
    SSL_CTX *ctx = create_server_ctx("certs/server.crt", "certs/server.key", "certs/ca.crt");
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return 1;
    }

    // 3. NETWORK - Setup Socket TCP (Livello 1)
    int server_socket_fd = create_tcp_socket();
    if (server_socket_fd < 0) {
        fprintf(stderr, "Failed to create server socket\n");
        return 1;
    }

    if (bind_socket(server_socket_fd, 8080) < 0) {
        fprintf(stderr, "Failed to bind to port 8080\n");
        close_socket(server_socket_fd);
        return 1;
    }

    int backlog = 5; // Valore standard
    if (listen_socket(server_socket_fd, backlog) < 0) {
        fprintf(stderr, "Failed to listen on port 8080\n");
        close_socket(server_socket_fd);
        return 1;
    }
    printf("Server is listening on port 8080...\n");
    
    // 4. NETWORK - Accettazione connessione TCP
    int client_socket_fd = accept_client(server_socket_fd);
    if (client_socket_fd < 0) {
        fprintf(stderr, "Failed to accept client connection\n");
        close_socket(server_socket_fd);
        return 1;
    }
    printf("Client connected via TCP. Starting TLS Handshake...\n");

    // 5. SSL - Handshake mTLS (Il "Ponte" tra Livello 1 e 2)
    // Trasformiamo la socket nuda in una sessione sicura
    SSL *ssl = accept_tls_connection(ctx, client_socket_fd);
    
    if (ssl) {
        printf("\n[!!!] TUNNEL mTLS STABILITO CON SUCCESSO [!!!]\n");
        printf("I dati scambiati ora sono cifrati e l'identità del client è verificata.\n\n");

        // --- Qui andrà il ciclo di comunicazione (Livello 3) ---
        // Esempio: SSL_read(ssl, buffer, sizeof(buffer));
        
        while(1) {
            // Ciclo di attesa comandi dal client
        }

        // Chiusura sicura della sessione SSL
        SSL_shutdown(ssl);
        SSL_free(ssl);
    } else {
        fprintf(stderr, "[-] TLS Handshake failed. Connection untrusted.\n");
    }

    // 6. CLEANUP
    close_socket(client_socket_fd);
    close_socket(server_socket_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
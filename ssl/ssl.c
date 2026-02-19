#include "ssl.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void init_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

void cleanup_openssl() {
    EVP_cleanup();
}

/* ========================================================================= *
 * CONTESTO SERVER (Richiede certificato al client)                          *
 * ========================================================================= */
SSL_CTX *create_server_ctx(const char *cert_file, const char *key_file, const char *ca_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("[-] Impossibile creare il contesto SSL Server");
        exit(EXIT_FAILURE);
    }

    // 1. Carichiamo l'identità del Server
    SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM);
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[-] Errore: la chiave privata del server non corrisponde.\n");
        exit(EXIT_FAILURE);
    }

    // 2. Carichiamo la Root CA (per poter verificare i client)
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) <= 0) {
        fprintf(stderr, "[-] Errore nel caricamento della Root CA nel Server.\n");
        exit(EXIT_FAILURE);
    }

    // 3. LA REGOLA D'ORO DELL'mTLS: Forza il client a presentare il certificato
    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT fa cadere la connessione se il client è sprovvisto di cert.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    printf("[+] Contesto SSL Server (mTLS) configurato con successo.\n");
    return ctx;
}

/* ========================================================================= *
 * CONTESTO CLIENT (Presenta il proprio certificato)                         *
 * ========================================================================= */
SSL_CTX *create_client_ctx(const char *cert_file, const char *key_file, const char *ca_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("[-] Impossibile creare il contesto SSL Client");
        exit(EXIT_FAILURE);
    }

    // 1. Carichiamo l'identità del Client (es. giuseppe.crt e giuseppe.key)
    SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM);
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[-] Errore: la chiave privata del client non corrisponde.\n");
        exit(EXIT_FAILURE);
    }

    // 2. Carichiamo la Root CA (per verificare che il server sia autentico)
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) <= 0) {
        fprintf(stderr, "[-] Errore nel caricamento della Root CA nel Client.\n");
        exit(EXIT_FAILURE);
    }

    // 3. Diciamo al client di verificare obbligatoriamente il server
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    printf("[+] Contesto SSL Client (mTLS) configurato con successo.\n");
    return ctx;
}

/* ========================================================================= *
 * FUNZIONI DI CONNESSIONE (Restano identiche a prima)                       *
 * ========================================================================= */
SSL *accept_tls_connection(SSL_CTX *ctx, int client_fd) {
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);
    printf("[*] Avvio dell'handshake TLS (in attesa del certificato client)...\n");

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    printf("[+] Handshake mTLS completato! Client autenticato.\n");
    return ssl;
}

SSL *connect_tls_to_server(SSL_CTX *ctx, int sockfd) {
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    printf("[*] Avvio dell'handshake TLS verso il server...\n");

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    printf("[+] Handshake mTLS completato! Server verificato.\n");
    return ssl;
}
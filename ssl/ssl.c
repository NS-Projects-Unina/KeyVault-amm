#include "ssl.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void init_openssl() {
    SSL_library_init(); 
    //Carica le Cipher Suites, altrimenti non avremmo nessuna suite disponibile per l'handshake TLS
    OpenSSL_add_all_algorithms(); //Carica tutti gli algoritmi di crittografia 
    SSL_load_error_strings(); //Carica le stringhe di errore per debugging 
}

void cleanup_openssl() {
    EVP_cleanup();
    //Per pulire la RAM da tabelle e dati usati da OpenSSL, ad esempio le chiavi in memoria.
}

/* ========================================================================= *
 *          CONTESTO SERVER (Richiede certificato al client)                          *
 * ========================================================================= */
SSL_CTX *create_server_ctx(const char *cert_file, const char *key_file, const char *ca_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method()); 
    //TLS_server_method() è una funzione che restituisce un puntatore a un oggetto SSL_METHOD che rappresenta il metodo TLS da utilizzare per il server.
    //Configura dunque il server per usare TLS e in modalità ascolto a negoziazioni.
    if (!ctx) {
        perror("[-] Impossibile creare il contesto SSL Server");
        exit(EXIT_FAILURE);
    }

    // 1. Carichiamo l'identità del Server
    SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM);  //Con cui il client verificherà l'identità del server
    SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM); //La chiave privata del server, usata per dimostrare al client di essere il legittimo proprietario del certificato presentato.
    if (!SSL_CTX_check_private_key(ctx)) {
        //Verifichiamo matematicamente che la chiave pubblica nel certificato corrisponda alla chiave privata. 
        //Se non corrispondono, c'è un errore di configurazione.
        fprintf(stderr, "[-] Errore: la chiave privata del server non corrisponde.\n");
        exit(EXIT_FAILURE);
    }

    // 2. Carichiamo la Root CA (per poter verificare i client)
    //Quando arriva un certificato dal client, il server userà questa RootCA per verificare la firma digitale.
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) <= 0) {
        fprintf(stderr, "[-] Errore nel caricamento della Root CA nel Server.\n");
        exit(EXIT_FAILURE);
    }

    // 3. mTLS: Forza il client a presentare il certificato
    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT fa cadere la connessione se il client è sprovvisto di cert.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    //Così durante l'handshake il server invierà CertificateRequest al client, chiedendo di presentare il proprio certificato per l'autenticazione.
    //Se il client risponde con no_certificate allora OpenSSL interrompe l'handshake e invia un Alert

    printf("[+] Contesto SSL Server (mTLS) configurato con successo.\n");
    return ctx;
}

/* ========================================================================= *
 * CONTESTO CLIENT (Presenta il proprio certificato)                         *
 * ========================================================================= */
SSL_CTX *create_client_ctx(const char *cert_file, const char *key_file, const char *ca_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    //Configuriamo il client per usare TLS in modalità negoziazione, ovvero a iniziare l'handshake TLS.
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
 *                      FUNZIONI DI CONNESSIONE 
 * ========================================================================= */
SSL *accept_tls_connection(SSL_CTX *ctx, int client_fd) {
    //Verrà chiamata dal server subito dopo che la socket TCP ha accettato la connessione del client.
    SSL *ssl = SSL_new(ctx);    //Oggetto Session TLS specifico per quel client singolo.
    SSL_set_fd(ssl, client_fd); //Colleghiamo la socket TCP del client al contesto SSL, così OpenSSL sa da quale socket leggere e scrivere i dati TLS criptati.
    printf("[*] Avvio dell'handshake TLS (in attesa del certificato client)...\n");


    /*
     *  Il server riceve il ClientHello, invia il proprio certificato e — dato che abbiamo impostato l'mTLS —
     *  invia una Certificate Request.
    */
    if (SSL_accept(ssl) <= 0) {
        //Se il client non invia un certificato valido, o ci sono altri problemi allora deve morire la connessione.
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        //Qua va chiusa anche la socket TCP associata?
        return NULL;
    }
    printf("[+] Handshake mTLS completato! Client autenticato.\n");
    return ssl;
}

SSL *connect_tls_to_server(SSL_CTX *ctx, int sockfd) {
    SSL *ssl = SSL_new(ctx); //Creazione Sessione specifica per questa connessione
    SSL_set_fd(ssl, sockfd); //Colleghiamo la socket TCP del client al contesto SSL, così OpenSSL sa da quale socket leggere e scrivere i dati TLS criptati.
    printf("[*] Avvio dell'handshake TLS verso il server...\n");

    if (SSL_connect(ssl) <= 0) {
        //Client invia ClientHello, riceve ServerHello e certificato del server, verifica il certificato del server e se qualcosa va storto (es. certificato non valido, firma digitale errata, ecc.) allora l'handshake fallisce.
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    printf("[+] Handshake mTLS completato! Server verificato.\n");
    return ssl;
}
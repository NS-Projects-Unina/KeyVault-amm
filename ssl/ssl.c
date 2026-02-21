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

    /* SETTING CRUCIALE
     * Chiediamo il certificato (SSL_VERIFY_PEER), ma NON forziamo il fallimento 
     * se manca (NON mettiamo SSL_VERIFY_FAIL_IF_NO_PEER_CERT).
     * Questo permette ad un nuovo client "nuovo" di entrare per fare l'ENROLL.
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    return ctx;
}


/* ========================================================================= *
 *                CONTESTO CLIENT: DUE LIVELLI DI SICUREZZA                  *
 * ========================================================================= */

// LIVELLO 1: TLS Semplice (Usato per ENROLLMENT)
// Verifica solo che il Server sia autentico, ma non presenta identità propria.
SSL_CTX *create_client_basic_ctx(const char *ca_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;

    // Carica solo la CA per verificare il certificato del Server
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) <= 0) return NULL;

    // Chiediamo di verificare il server
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    printf("[*] Contesto Client BASIC (Solo verifica Server) pronto.\n");
    return ctx;
}

// LIVELLO 2: mTLS Completo (Usato per VAULT)
// Richiede obbligatoriamente cert e key dell'utente
SSL_CTX *create_client_mtls_ctx(const char *cert_file, const char *key_file, const char *ca_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method()); //Creazione del contesto TLS per il client, che useremo per stabilire la connessione mTLS con il server.
    if (!ctx) return NULL; //Se non riesce a creare il contesto, ritorna NULL per segnalare l'errore.

    // Carichiamo l'identità del Client (es. giuseppe.crt e giuseppe.key)
    SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM);
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[-] Errore: la chiave privata del client non corrisponde.\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) <= 0) return NULL;

    // Diciamo al client di verificare obbligatoriamente il server
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    printf("[+] Contesto Client mTLS (Identità Digitale) pronto.\n");
    return ctx;
}

/* ========================================================================= *
 *                      FUNZIONI DI CONNESSIONE 
 * ========================================================================= */
SSL *accept_tls_connection(SSL_CTX *ctx, int client_fd) {
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);
    
    printf("[*] Inizio negoziazione TLS (Porta Ibrida mTLS/Enrollment)...\n");

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    // --- MODIFICA LOGICA ---
    // Verifichiamo subito se il client ha presentato un certificato o no
    X509 *client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert) {
        printf("[+] Handshake completato: Connessione mTLS (Autenticata).\n");
        X509_free(client_cert); // Fondamentale liberare la memoria
    } else {
        printf("[!] Handshake completato: Connessione TLS Semplice (Anonima/Enrollment).\n");
    }

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


// Funzione di utilità per estrarre il Common Name (CN) dal certificato del client, se presente.
int get_client_common_name(SSL *ssl, char *out_cn, size_t len) {
    if (!ssl) return -1;

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) return 0; // Sessione TLS Semplice (nessun certificato)

    // Estrazione del testo dal campo CN del Subject
    X509_NAME *subject_name = X509_get_subject_name(cert);
    if (X509_NAME_get_text_by_NID(subject_name, NID_commonName, out_cn, len) < 0) {
        X509_free(cert);
        return -1;
    }

    X509_free(cert);
    return 1; // Successo mTLS
}
#include "ssl_client.h"
#include "ssl_server.h"
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

/* ========================================================================= *
 * CORE: INIZIALIZZAZIONE E CLEANUP (Condivisi)                              *
 * ========================================================================= */


void init_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

void cleanup_openssl() {
    EVP_cleanup();
}

/* ========================================================================= *
 * UTILITY INTERNA: CALCOLO FINGERPRINT (Condivisa)                          *
 * ========================================================================= */

static int internal_compute_hash(EVP_PKEY *pubkey, char *out_hex, size_t len) {
    if (!pubkey || len < 65) return -1;

    unsigned char *der = NULL;
    int der_len = i2d_PUBKEY(pubkey, &der);
    if (der_len < 0) return -1;

    unsigned char hash[32]; // SHA256_DIGEST_LENGTH
    SHA256(der, der_len, hash);

    for (int i = 0; i < 32; i++) {
        sprintf(out_hex + (i * 2), "%02x", hash[i]);
    }
    out_hex[64] = '\0';

    if (der) OPENSSL_free(der);
    return 0;
}

/* ========================================================================= *
 * IMPLEMENTAZIONE LATO SERVER (ssl_server.h)                                *
 * ========================================================================= */

SSL_CTX *create_server_ctx(const char *cert_file, const char *key_file, const char *ca_file) {
    //Creo un oggetto SSL_CTX, la fabbrica per le future connessioni
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method()); 
    /*TLS_server_method(): istruzione che consente al server di negoziare 
        automaticamente la versione più alta di TLS disponibile.
    */

    if (!ctx) return NULL;

    //Carico l'identità del Server nel consteso
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    /*
        Verifica matematica che la chiave privata corrisponda
        alla chiave pubblica contenuta nel certificato.
    */
    if (!SSL_CTX_check_private_key(ctx)) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    //Indica al server di chi può fidarsi, caricando il certificato ca.crt
    //Stiamo indicando al server che può affidarsi dei certificatil
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) <= 0) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return ctx;
}

SSL *accept_tls_connection(SSL_CTX *ctx, int client_fd) {

    if(!ctx){
        fprintf(stderr, "[-] Errore: Contesto SSL nullo in accept_tls_connection\n");
        return NULL;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) return NULL;
    SSL_set_fd(ssl, client_fd);
    
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    return ssl;
}

int get_client_full_identity(SSL *ssl, char *out_cn, size_t cn_len, char *out_fingerprint, size_t fp_len) {
    if (!ssl) return -1;

    //Tentiamo di estrarre l'oggetto X509, certificato inviato dal client.
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) return 0; //In enrollment, finiremo sempre qui.

    //Estraiamo il CN, dato puramente informativo
    X509_NAME *subject_name = X509_get_subject_name(cert);
    X509_NAME_get_text_by_NID(subject_name, NID_commonName, out_cn, cn_len);

    //Questa funzione dà in output il Fingerprinting
    int res = get_certificate_fingerprint(cert, out_fingerprint, fp_len);
    X509_free(cert);
    return (res == 0) ? 1 : -1;
}

int get_csr_fingerprint(X509_REQ *csr, char *out_hex, size_t len) {
    if (!csr) return -1;
    EVP_PKEY *pubkey = X509_REQ_get_pubkey(csr);
    int res = internal_compute_hash(pubkey, out_hex, len);
    if (pubkey) EVP_PKEY_free(pubkey);
    return res;
}

/* ========================================================================= *
 * IMPLEMENTAZIONE LATO CLIENT (ssl_client.h)                                *
 * ========================================================================= */

SSL_CTX *create_client_basic_ctx(const char *ca_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;

    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) <= 0) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return ctx;
}

SSL_CTX *create_client_mtls_ctx(const char *cert_file, const char *key_file, const char *ca_file) {
    SSL_CTX *ctx = create_client_basic_ctx(ca_file);
    if (!ctx) return NULL;

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

SSL *connect_tls_to_server(SSL_CTX *ctx, int sockfd) {
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    return ssl;
}

int get_certificate_fingerprint(X509 *cert, char *out_hex, size_t len) {
    if (!cert) return -1;
    //Prelevo la chiave pubblica dal certificato
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    //Calcolo il fingerprinting
    int res = internal_compute_hash(pubkey, out_hex, len);
    if (pubkey) EVP_PKEY_free(pubkey);
    return res;
}

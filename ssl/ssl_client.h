#ifndef SSL_CLIENT_H
#define SSL_CLIENT_H

#include <openssl/ssl.h>

// Inizializzazione comune
void init_openssl();
void cleanup_openssl();

// Gestione Contesti (OOB: passerai i path di client_storage)
SSL_CTX *create_client_basic_ctx(const char *ca_file);
SSL_CTX *create_client_mtls_ctx(const char *cert_file, const char *key_file, const char *ca_file);

// Connessione
SSL *connect_tls_to_server(SSL_CTX *ctx, int sockfd);

// Utility Identità
int get_certificate_fingerprint(X509 *cert, char *out_hex, size_t len);

#endif
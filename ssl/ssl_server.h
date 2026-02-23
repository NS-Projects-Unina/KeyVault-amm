#ifndef SSL_SERVER_H
#define SSL_SERVER_H

#include <openssl/ssl.h>

// Inizializzazione comune
void init_openssl();
void cleanup_openssl();

// Gestione Contesto (passerai i path di server_storage)
SSL_CTX *create_server_ctx(const char *cert_file, const char *key_file, const char *ca_file);

// Accettazione
SSL *accept_tls_connection(SSL_CTX *ctx, int client_fd);

// Utility Identità e CSR
int get_client_full_identity(SSL *ssl, char *out_cn, size_t cn_len, char *out_fingerprint, size_t fp_len);
int get_csr_fingerprint(X509_REQ *csr, char *out_hex, size_t len);

#endif
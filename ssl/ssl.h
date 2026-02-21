#ifndef SSL_H
#define SSL_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

//Inizializzazione e Cleanup 
void init_openssl();
void cleanup_openssl();

/* 
 * Contesto Server Ibrido
 * Permette sia mTLS (Vault) che TLS Semplice (Enrollment) sulla stessa porta.
 */
SSL_CTX *create_server_ctx(const char *cert_file, const char *key_file, const char *ca_file);


//Contesti Client a due livelli 
// LIVELLO 1: TLS Semplice per fase di ENROLLMENT (Verifica solo il Server)
SSL_CTX *create_client_basic_ctx(const char *ca_file);
// LIVELLO 2: mTLS Completo per fase operativa VAULT (Presenta identità propria)
SSL_CTX *create_client_mtls_ctx(const char *cert_file, const char *key_file, const char *ca_file);


//Gestione delle Connessioni e Handshake 
SSL *accept_tls_connection(SSL_CTX *ctx, int client_fd);
SSL *connect_tls_to_server(SSL_CTX *ctx, int sockfd);

//Utilità di Identità
int get_client_full_identity(SSL *ssl, char *out_cn, size_t cn_len, char *out_fingerprint, size_t fp_len);
int get_certificate_fingerprint(X509 *cert, char *out_hex, size_t len);
int get_csr_fingerprint(X509_REQ *csr, char *out_hex, size_t len);

#endif // SSL_H
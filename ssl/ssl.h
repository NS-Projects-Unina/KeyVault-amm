//L'obiettivo è considerare i socketdescriptor e avvolgerlo nel contesto OpenSSL
#ifndef SSL_H
#define SSL_H
#include <openssl/ssl.h>
#include <openssl/err.h>

// Inizializzazione e Pulizia Globale
void init_openssl();
void cleanup_openssl();

// Creazione dei Contesti mTLS
SSL_CTX *create_server_ctx(const char *cert_file, const char *key_file, const char *ca_file);
SSL_CTX *create_client_ctx(const char *cert_file, const char *key_file, const char *ca_file);

// Avvio dell'Handshake TLS sulle socket TCP
SSL *accept_tls_connection(SSL_CTX *ctx, int client_fd);
SSL *connect_tls_to_server(SSL_CTX *ctx, int sockfd);

#endif // SSL_H


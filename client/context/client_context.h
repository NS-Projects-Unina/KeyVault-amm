#ifndef CLIENT_CONTEXT_H
#define CLIENT_CONTEXT_H

#include <openssl/ssl.h>

// Definizione dei metodi di derivazione/lettura della chiave
typedef enum {
    CRYPTO_METHOD_NONE = 0,
    CRYPTO_METHOD_PASSWORD,
    CRYPTO_METHOD_USB
} CryptoMethod;

// --- Rete e Configurazione ---
void client_context_set_server_ip(const char *ip);
const char* client_context_get_server_ip();

void client_context_set_server_port(int port);
int client_context_get_server_port();

// --- Connessione SSL ---
void client_context_set_ssl(SSL *ssl);
SSL* client_context_get_ssl();

void client_context_set_sockfd(int fd);
int client_context_get_sockfd();

// --- Utente ---
void client_context_set_username(const char *user);
const char* client_context_get_username();

// --- Gestione Intento Crittografico ---
void client_context_set_crypto_method(CryptoMethod method, const char *credential);
CryptoMethod client_context_get_crypto_method();
const char* client_context_get_crypto_credential();
int client_context_is_crypto_ready();

#endif // CLIENT_CONTEXT_H
#ifndef CLIENT_CONTEXT_H
#define CLIENT_CONTEXT_H

#include <openssl/ssl.h>
#include "crypto_utils.h"

// --- Configurazione Rete ---
void client_context_set_server_ip(const char *ip);
const char* client_context_get_server_ip();
int client_context_get_server_port();

// --- Identità Utente  ---
void client_context_set_username(const char *user);
const char* client_context_get_username();

// --- Stato Sessione ---
void client_context_set_ssl(SSL *ssl);
SSL* client_context_get_ssl();
void client_context_set_sockfd(int fd);
int client_context_get_sockfd();

// --- Sicurezza ---
void client_context_set_session_key(const unsigned char *key);
unsigned char* client_context_get_session_key();
int client_context_is_crypto_ready();

#endif
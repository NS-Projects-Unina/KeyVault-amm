#include "client_context.h"
#include "client_utils.h"
#include <string.h>

static char global_server_ip[64] = "127.0.0.1"; // Default
static int global_server_port = 8080;          // Default

static char current_username[128] = ""; // Inizialmente vuoto

static SSL *active_ssl = NULL;
static int active_sockfd = -1;

// --- Variabili per l'intento crittografico al posto della session_key fissa ---
static CryptoMethod current_crypto_method = CRYPTO_METHOD_NONE;
static char current_crypto_credential[512] = ""; 

void client_context_set_server_ip(const char *ip) {
    if (ip && strlen(ip) > 0) {
        strncpy(global_server_ip, ip, sizeof(global_server_ip) - 1);
    }
}

const char* client_context_get_server_ip() { return global_server_ip; }

void client_context_set_server_port(int port) { global_server_port = port; }
int client_context_get_server_port() { return global_server_port; }

void client_context_set_ssl(SSL *ssl) { active_ssl = ssl; }
SSL* client_context_get_ssl() { return active_ssl; }

void client_context_set_sockfd(int fd) { active_sockfd = fd; }
int client_context_get_sockfd() { return active_sockfd; }

void client_context_set_username(const char *user) {
    if (user) {
        strncpy(current_username, user, sizeof(current_username) - 1);
    }
}

const char* client_context_get_username() {    
    return current_username;
}

// --- Implementazione Gestione Intento Crittografico ---
void client_context_set_crypto_method(CryptoMethod method, const char *credential) {
    current_crypto_method = method;
    if (credential) {
        strncpy(current_crypto_credential, credential, sizeof(current_crypto_credential) - 1);
        current_crypto_credential[sizeof(current_crypto_credential) - 1] = '\0';
    } else {
        current_crypto_credential[0] = '\0';
    }
}

CryptoMethod client_context_get_crypto_method() {
    return current_crypto_method;
}

const char* client_context_get_crypto_credential() {
    return current_crypto_credential;
}

int client_context_is_crypto_ready() {
    // Se è PASSWORD, siamo pronti a prescindere (la password arriverà "live" dai popup)
    if (current_crypto_method == CRYPTO_METHOD_PASSWORD) return 1;
    
    // Se è USB, dobbiamo anche avere un path valido salvato
    if (current_crypto_method == CRYPTO_METHOD_USB && strlen(current_crypto_credential) > 0) return 1;
    
    return 0; // Altrimenti non siamo pronti
}
#include "client_context.h"
#include "client_utils.h"
#include <string.h>

static char global_server_ip[64] = "127.0.0.1"; // Default
static int global_server_port = 8080;          // Default

static char current_username[128] = ""; // Inizialmente vuoto

static SSL *active_ssl = NULL;
static int active_sockfd = -1;

static unsigned char session_key[32]; // AES_KEY_LEN
static int crypto_ready = 0;

void client_context_set_server_ip(const char *ip) {
    if (ip && strlen(ip) > 0) {
        strncpy(global_server_ip, ip, sizeof(global_server_ip) - 1);
    }
}

const char* client_context_get_server_ip() {return global_server_ip;}

void client_context_set_server_port(int port) {global_server_port = port;}
int client_context_get_server_port() {return global_server_port;}

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



void client_context_set_session_key(const unsigned char *key) {
    memcpy(session_key, key, 32);
    crypto_ready = 1;
}
unsigned char* client_context_get_session_key() { return session_key; }
int client_context_is_crypto_ready() { return crypto_ready; }
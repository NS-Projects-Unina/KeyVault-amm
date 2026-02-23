#ifndef CLIENT_CONTEXT_H
#define CLIENT_CONTEXT_H

// Funzioni per gestire l'IP del Server
void client_context_set_server_ip(const char *ip);
const char* client_context_get_server_ip();

// Funzioni per la Porta (se volessi renderla dinamica in futuro)
void client_context_set_server_port(int port);
int client_context_get_server_port();

#endif
#ifndef CLIENT_SERVICE_H
#define CLIENT_SERVICE_H

#include <stddef.h>

// Inizializzazione sessione mTLS
int client_service_init_session();

// Impostazione chiave di sessione
void client_service_set_session_key(const unsigned char *key);

// Salvataggio credenziale (Restituisce int e accetta buffer per risposta server)
int client_service_store_data_encrypted(const char *svc, const char *pass, char *out_server_resp, size_t resp_len);

// Recupero credenziali (Versione agnostica con callback)
void client_service_fetch_vault(void (*data_handler)(const char *svc, const char *pass));

// Funzione legacy (se ancora usata dal vecchio controller per debug CLI)
void client_service_fetch_data_encrypted();

void client_service_close_session();

#endif
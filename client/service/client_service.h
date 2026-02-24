#ifndef CLIENT_SERVICE_H
#define CLIENT_SERVICE_H

#include <stddef.h>

// Configurazione base
void client_service_set_server_config(const char *ip);
void client_service_set_default_username();
const char* client_service_get_username();
int client_service_import_ca(const char *source_path);

// Gestione chiavi
int client_service_unlock_with_password(const char *password);
int client_service_unlock_with_usb(const char *path);
int client_service_generate_new_usb_key(const char *path);

// Sessione mTLS
int client_service_init_session(void);
void client_service_close_session(void);

// Vault: Protocollo e Parsing
int client_service_store_data(const char *svc, const char *pass, char *out_server_resp, size_t resp_len);
void client_service_fetch_and_parse_vault(void (*data_handler)(const char *svc, const char *pass));

#endif // CLIENT_SERVICE_H
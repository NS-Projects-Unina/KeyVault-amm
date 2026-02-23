#ifndef CLIENT_SERVICE_H
#define CLIENT_SERVICE_H

#include <stddef.h>

// Funzioni di Configurazione (Ponte verso il Context)
void client_service_set_server_config(const char *ip);
void client_service_set_default_username();
void client_service_set_username(const char *username); // Aggiunta per la GUI
const char* client_service_get_username();

// Funzioni di Sessione e Vault
int client_service_init_session(void);
void client_service_set_session_key(const unsigned char *key);
int client_service_store_data_encrypted(const char *svc, const char *pass, char *out_resp, size_t len);
void client_service_fetch_vault(void (*data_handler)(const char *svc, const char *pass));
void client_service_close_session(void);

// Sblocco Sessione (Logica Crittografica)
int client_service_unlock_with_password(const char *password);
int client_service_unlock_with_usb(const char *path);


int client_service_has_ca(void);
int client_service_import_ca(const char *source_path);


#endif // CLIENT_SERVICE_H
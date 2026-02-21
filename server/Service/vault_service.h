#ifndef VAULT_SERVICE_H
#define VAULT_SERVICE_H

#include <stddef.h>

// --- Ciclo di Vita --- 
int vault_service_init_system();
int vault_service_accept_client(char *out_identity, size_t max_len);
void vault_service_close_client();
void vault_service_shutdown();

// --- I/O di Rete Astratto --- 
int vault_service_read_data(char *buffer, int max_len);
int vault_service_send_data(const char *data);

// --- Logica di Business --- 
int vault_service_save_credential(const char *user, const char *svc, const char *blob);
char* vault_service_get_all(const char *user);

// Aggiungi questa riga sotto le altre dichiarazioni:
int vault_service_process_enrollment(const char *user, const char *pass, const char *csr_content);

#endif
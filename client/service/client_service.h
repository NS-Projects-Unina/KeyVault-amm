#ifndef CLIENT_SERVICE_H
#define CLIENT_SERVICE_H

int client_service_init_session();
void client_service_store_data_encrypted(const char *svc, const char *pass);
void client_service_fetch_data();

int client_service_prepare_crypto_key(unsigned char *out_key);
// Funzione per generare la chiave USB senza sporcare il controller
int client_service_bootstrap_crypto();
void client_service_close_session();

#endif
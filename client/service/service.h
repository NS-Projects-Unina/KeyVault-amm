#ifndef CLIENT_SERVICE_H
#define CLIENT_SERVICE_H

// Funzioni di servizio
const char* get_system_user();

// Controlla fisicamente se nella cartella /certs esiste un file .crt con il nome dell'utente di sistema.
int client_service_needs_enrollment();

// Richiede al server di generare un OTP per l'utente 
int client_service_request_enrollment(const char *user);

// Invia al server il CSR insieme all'OTP per ottenere il certificato
int client_service_perform_enrollment(const char *user, const char *otp);

// Avvia il setup PKI basato sull'utente di sistema e stabilisce l'mTLS
int client_service_init_session();

// Invia una credenziale al server
void client_service_store_data(const char *service_name, const char *password);

// Richiede tutte le credenziali dal server
void client_service_fetch_data();

// Pulisce memoria, chiude socket e spegne il tunnel SSL
void client_service_close_session();


#endif
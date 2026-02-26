#ifndef CLIENT_CONTROLLER_H
#define CLIENT_CONTROLLER_H

#include <stddef.h>

// --- Configurazione e Utente ---
void controller_set_server_config(const char *ip);
const char* controller_get_username();
const char* controller_get_system_user();

// --- Setup CA ---
int controller_check_client_has_ca();
int controller_import_ca(const char *source_path);

// --- Enrollment ---
int controller_needs_enrollment();
int controller_request_enrollment(const char *user);
int controller_perform_enrollment(const char *user, const char *otp);

// --- Gestione Chiavi e Cifratura ---
int controller_set_crypto_password(); 
int controller_set_crypto_usb_path(const char *path);
int controller_generate_new_usb_key(const char *path);
int controller_is_using_password();
// --- Sessione e Vault ---
int controller_init_session();int controller_store_data_encrypted(const char *svc, const char *pass, const char *live_pw, char *out_server_resp, size_t resp_len);
int controller_fetch_vault(const char *live_pw, void (*data_handler)(const char *svc, const char *pass));
void controller_set_default_username();


#endif // CLIENT_CONTROLLER_H
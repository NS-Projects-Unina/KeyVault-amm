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

// --- Gestione Chiavi e Sblocco ---
int controller_unlock_with_password(const char *password);
int controller_unlock_with_usb(const char *path);
int controller_generate_new_usb_key(const char *path);

// --- Sessione e Vault ---
int controller_init_session();
int controller_store_data_encrypted(const char *svc, const char *pass, char *out_server_resp, size_t resp_len);
void controller_fetch_vault(void (*data_handler)(const char *svc, const char *pass));
void controller_set_default_username();


#endif // CLIENT_CONTROLLER_H
#ifndef VAULT_SERVICE_H
#define VAULT_SERVICE_H

#include <stddef.h>
#include <openssl/ssl.h>

// --- Ciclo di Vita del Sistema ---
int vault_service_init_system();
void vault_service_shutdown();

/**
 * Accetta un client e restituisce il contesto SSL della connessione.
 * Il chiamante è responsabile di chiudere la connessione con vault_service_close_client().
 * @param out_fp       Buffer dove scrivere il fingerprint del certificato client.
 * @param fp_len       Dimensione del buffer out_fp.
 * @param out_user     Buffer dove scrivere lo username (CN) del client.
 * @param user_len     Dimensione del buffer out_user.
 * @param out_ssl      Puntatore dove scrivere l'oggetto SSL* della connessione.
 * @return 1 se mTLS (autenticato), 0 se TLS semplice (anonimo), -1 in caso di errore.
 */
int vault_service_accept_client(char *out_fp, size_t fp_len,
                                char *out_user, size_t user_len,
                                SSL **out_ssl);

/**
 * Chiude e libera la connessione SSL di un client.
 * Da chiamare al termine di ogni sessione (anche in caso di errore).
 */
void vault_service_close_client(SSL *ssl);

// --- I/O di Rete (ora thread-safe: operano sul proprio SSL*) ---
int  vault_service_read_data(SSL *ssl, char *buffer, int max_len);
int  vault_service_send_data(SSL *ssl, const char *data);

// --- Logica di Enrollment ---
int vault_service_request_enrollment(const char *user, const char *otp);
int vault_service_process_enrollment(SSL *ssl, const char *user,
                                     const char *otp, const char *csr_content);

// --- Logica di Business (Vault) ---
int   vault_service_save_credential(const char *fp, const char *svc, const char *blob);
char *vault_service_get_all(const char *fp);

// --- Utility ---
void generate_random_otp(char *out, size_t len);

#endif
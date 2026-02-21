#ifndef DAL_H
#define DAL_H   

#include <stdio.h>

/* ========================================================================= *
 * GESTIONE IDENTITÀ (users.dat)                                             *
 * ========================================================================= */

// Registra il nuovo utente e crea il suo file vault personale
int dal_register_user(const char *fp, const char *user);

// Verifica se la CHIAVE (fingerprint) è già registrata
int dal_fingerprint_exists(const char *fp);

// Verifica se lo USERNAME è già occupato
int dal_username_taken(const char *user);

// Novità: Recupera lo username associato a un fingerprint (per i log del server)
int dal_get_username_by_fingerprint(const char *fp, char *out_user, size_t size);

/* ========================================================================= *
 * GESTIONE VAULT INDIVIDUALE (vaults/[fp].dat)                              *
 * ========================================================================= */

// Modificato: Ora salva usando il fingerprint per individuare il file corretto
int dal_save_record(const char *fp, const char *service, const char *encrypted_blob);

// Modificato: Recupera TUTTI i dati associati a quel fingerprint
char* dal_fetch_all_records(const char *fp);

/* ========================================================================= *
 * GESTIONE OTP (pending_requests.dat)                                       *
 * ========================================================================= */

// Salva una richiesta di enrollment in attesa di approvazione
int dal_save_pending_request(const char *user, const char *otp);

// Verifica l'OTP e lo rimuove (burn) se corretto
int dal_verify_and_burn_otp(const char *user, const char *provided_otp);

#endif
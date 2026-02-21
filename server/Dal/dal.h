#ifndef DAL_H
#define DAL_H   

#include <stdio.h>

// Aggiornato: ora accetta anche il nome del servizio
int dal_save_record(const char *username, const char *service, const char *encrypted_blob);

// Novità: Recupera i dati associati a un utente formattati in stringa
char* dal_get_records_by_user(const char *username);

// Verifica se la CHIAVE è già registrata (Colonna 0)
int dal_fingerprint_exists(const char *fp);

// Verifica se lo USERNAME è già occupato (Colonna 1)
int dal_username_taken(const char *user);

// Registra il nuovo utente (Inizializza la riga)
int dal_register_user(const char *fp, const char *user);

// Nuova funzione per gestire le richieste di Enroll in sospeso (OTP)
int dal_save_pending_request(const char *user, const char *otp);

// Verifica l'OTP fornito e, se corretto, lo "brucia" rimuovendolo dal file
int dal_verify_and_burn_otp(const char *user, const char *provided_otp);
#endif
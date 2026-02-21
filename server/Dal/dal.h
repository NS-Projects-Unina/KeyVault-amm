#ifndef DAL_H
#define DAL_H   

#include <stdio.h>

// Aggiornato: ora accetta anche il nome del servizio
int dal_save_record(const char *username, const char *service, const char *encrypted_blob);

// Novità: Recupera i dati associati a un utente formattati in stringa
char* dal_get_records_by_user(const char *username);

#endif
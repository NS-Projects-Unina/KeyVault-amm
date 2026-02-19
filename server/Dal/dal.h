#ifndef DAL_H
#define DAL_H   

#include <stdio.h>

// Aggiornato: ora accetta anche il nome del servizio
int dal_save_record(const char *username, const char *service, const char *encrypted_blob);

#endif
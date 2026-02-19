#include "dal.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define VAULT_FILE "vault.dat"

int dal_save_record(const char *username, const char *service, const char *encrypted_blob) {
    FILE *fp = fopen(VAULT_FILE, "ab"); 
    if (!fp) return -1;

    // Scrittura formattata: username|servizio|dati
    fprintf(fp, "%s|%s|%s\n", username, service, encrypted_blob);
    
    fclose(fp);
    return 0;
}

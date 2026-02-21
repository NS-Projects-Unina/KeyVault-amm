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

/* ========================================================================= *
 * NUOVA FUNZIONE: Recupero dati sicuro anti-crash                           *
 * ========================================================================= */
char* dal_get_records_by_user(const char *username) {
    FILE *fp = fopen(VAULT_FILE, "rb");
    if (!fp) return NULL; // Se il file non esiste, vault vuoto

    // Usiamo calloc per essere certi che la memoria parta tutta azzerata
    char *result = calloc(8192, sizeof(char)); 
    if (!result) { fclose(fp); return NULL; }

    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        // Pulisce la riga da \r e \n spuri che rompono strtok
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0) continue; 

        char line_copy[2048];
        strcpy(line_copy, line);

        char *user = strtok(line_copy, "|");
        
        // Verifica rigorosa su user prima di fare strcmp
        if (user != NULL && strcmp(user, username) == 0) {
            char *svc = strtok(NULL, "|");
            char *data = strtok(NULL, "|"); 
            
            // Verifichiamo che i pezzi ci siano tutti
            if (svc && data) {
                // Sicurezza: Evitiamo il buffer overflow su result
                if (strlen(result) + strlen(svc) + strlen(data) + 10 < 8000) {
                    strcat(result, svc);
                    strcat(result, ": ");
                    strcat(result, data);
                    strcat(result, "\n");
                }
            }
        }
    }

    fclose(fp);
    return result;
}
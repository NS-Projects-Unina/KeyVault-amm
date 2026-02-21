#include "dal.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define PENDING_FILE "pending_requests.dat"
#define DB_FILE "vault.dat"

int dal_save_record(const char *username, const char *service, const char *encrypted_blob) {
    FILE *fp = fopen(DB_FILE, "ab"); 
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
    FILE *fp = fopen(DB_FILE, "rb");
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


// Helper per verificare se un valore esiste in una specifica colonna
static int check_db_field(const char *value, int column_index) {
    FILE *f = fopen(DB_FILE, "r");
    if (!f) return 0; // Se il file non esiste, il campo non è "preso"

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        char *token = strtok(line, "|");
        int current_col = 0;
        while (token) {
            if (current_col == column_index && strcmp(token, value) == 0) {
                fclose(f);
                return 1; // Trovato!
            }
            token = strtok(NULL, "|");
            current_col++;
        }
    }
    fclose(f);
    return 0; // Non trovato
}

// Verifica se la CHIAVE è già registrata (Colonna 0)
int dal_fingerprint_exists(const char *fp) {
    return check_db_field(fp, 0);
}

// Verifica se lo USERNAME è già occupato (Colonna 1)
int dal_username_taken(const char *user) {
    return check_db_field(user, 1);
}

// Registra il nuovo utente (Inizializza la riga)
int dal_register_user(const char *fp, const char *user) {
    FILE *f = fopen(DB_FILE, "a"); // Apriamo in "append" (aggiungi in fondo)
    if (!f) return -1;

    // Scriviamo: fingerprint|username| (il vault all'inizio è vuoto)
    fprintf(f, "%s|%s|\n", fp, user);
    fclose(f);
    
    printf("[*] DAL: Nuovo utente registrato con successo nel database.\n");
    return 0;
}


//OTP GESTIONE
int dal_save_pending_request(const char *user, const char *otp) {
    if (dal_username_taken(user)) return -1;

    FILE *f = fopen(PENDING_FILE, "a");
    if (!f) return -1;

    // Scriviamo un formato pulito e facile da rileggere
    fprintf(f, "USER: %s | OTP: %s | DATA: %ld\n", user, otp, (long)time(NULL));
    fclose(f);
    return 0;
}

int dal_verify_and_burn_otp(const char *user, const char *provided_otp) {
    FILE *f = fopen(PENDING_FILE, "r"); // Usa la macro!
    if (!f) return -1;

    FILE *tmp = fopen("pending_requests.tmp", "w");
    if (!tmp) { fclose(f); return -1; }

    char line[512];
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        char u[256], o[256];
        
        // Il segreto qui è far corrispondere ESATTAMENTE il formato della fprintf sopra
        // sscanf restituisce il numero di elementi letti correttamente
        if (sscanf(line, "USER: %255s | OTP: %255s", u, o) == 2) {
            if (strcmp(user, u) == 0 && strcmp(provided_otp, o) == 0) {
                found = 1; 
                printf("[*] DAL: OTP per '%s' verificato e rimosso.\n", user);
                continue; // Salta la scrittura nel file tmp -> l'OTP è "bruciato"
            }
        }
        fputs(line, tmp);
    }

    fclose(f);
    fclose(tmp);
    
    // Sostituisci il file vecchio con quello senza l'OTP usato
    rename("pending_requests.tmp", PENDING_FILE);

    return (found) ? 0 : -1;
}


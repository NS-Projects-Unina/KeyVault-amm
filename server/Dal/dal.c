#include "dal.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h> // Per mkdir
#include <unistd.h>

#define PENDING_FILE  "pending_requests.dat"
#define USER_REGISTRY "users.dat"
#define VAULTS_DIR    "vaults/"

/* --- HELPER: Genera il percorso del file vault dall'hash --- */
static void get_vault_path(const char *fp, char *out_path, size_t size) {
    snprintf(out_path, size, "%s%s.dat", VAULTS_DIR, fp);
}

/* ========================================================================= *
 * 1. GESTIONE IDENTITÀ (users.dat)                                          *
 * ========================================================================= */

// Verifica se un campo (fp o user) esiste nel registro anagrafico
static int check_user_registry(const char *value, int column_index) {
    FILE *f = fopen(USER_REGISTRY, "r");
    if (!f) return 0;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *token = strtok(line, "|");
        int current_col = 0;
        while (token) {
            if (current_col == column_index && strcmp(token, value) == 0) {
                fclose(f);
                return 1;
            }
            token = strtok(NULL, "|");
            current_col++;
        }
    }
    fclose(f);
    return 0;
}

int dal_fingerprint_exists(const char *fp) { return check_user_registry(fp, 0); }
int dal_username_taken(const char *user)   { return check_user_registry(user, 1); }

int dal_register_user(const char *fp, const char *user) {
    // 1. Assicuriamoci che la cartella vaults esista
    mkdir(VAULTS_DIR, 0700);

    // 2. Registrazione in users.dat
    FILE *f = fopen(USER_REGISTRY, "a");
    if (!f) return -1;
    fprintf(f, "%s|%s\n", fp, user);
    fclose(f);

    // 3. Creazione file vault individuale vuoto
    char path[512];
    get_vault_path(fp, path, sizeof(path));
    FILE *v = fopen(path, "wb");
    if (v) fclose(v);

    printf("[*] DAL: Utente '%s' registrato e vault creato.\n", user);
    return 0;
}

/* ========================================================================= *
 * 2. GESTIONE VAULT INDIVIDUALE (vaults/[fp].dat)                           *
 * ========================================================================= */

// SALVA: Scrive nel file specifico dell'utente
int dal_save_record(const char *fp, const char *service, const char *encrypted_blob) {
    char path[512];
    get_vault_path(fp, path, sizeof(path));

    FILE *f = fopen(path, "ab"); // Append binario
    if (!f) return -1;

    // Formato interno: Servizio|Blob
    fprintf(f, "%s|%s\n", service, encrypted_blob);
    fclose(f);
    return 0;
}

char* dal_fetch_all_records(const char *fp) {
    char path[512];
    get_vault_path(fp, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return strdup("[-] Nessun dato trovato.\n");

    char *result = calloc(8192, 1);
    if (!result) { fclose(f); return NULL; }

    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0; 
        if (strlen(line) == 0) continue;

        // Mandiamo semplicemente "servizio|hex_cifrato\n"
        if (strlen(result) + strlen(line) + 2 < 8000) {
            strcat(result, line);
            strcat(result, "\n");
        }
    }
    fclose(f);
    return result; // Ora il client riceverà: Amazon|a1b2c3...
}

/* ========================================================================= *
 * 3. GESTIONE OTP (Invariata ma con Macro corretta)                         *
 * ========================================================================= */

int dal_save_pending_request(const char *user, const char *otp) {
    if (dal_username_taken(user)) return -1;
    FILE *f = fopen(PENDING_FILE, "a");
    if (!f) return -1;
    fprintf(f, "USER: %s | OTP: %s | DATA: %ld\n", user, otp, (long)time(NULL));
    fclose(f);
    return 0;
}

int dal_verify_and_burn_otp(const char *user, const char *provided_otp) {
    FILE *f = fopen(PENDING_FILE, "r");
    if (!f) return -1;
    FILE *tmp = fopen("pending_requests.tmp", "w");
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char u[256], o[256];
        if (sscanf(line, "USER: %255s | OTP: %255s", u, o) == 2) {
            if (strcmp(user, u) == 0 && strcmp(provided_otp, o) == 0) {
                found = 1;
                continue;
            }
        }
        fputs(line, tmp);
    }
    fclose(f);
    fclose(tmp);
    rename("pending_requests.tmp", PENDING_FILE);
    return (found) ? 0 : -1;
}
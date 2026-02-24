#include "client_utils.h"
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>

const char* get_system_user() {
    struct passwd *pw = getpwuid(getuid());
    return (pw) ? pw->pw_name : "default_user";
}

int load_file_to_buffer(const char *path, char *buffer, size_t size) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(buffer, 1, size - 1, f);
    buffer[n] = '\0';
    fclose(f);
    return 0;
}

int save_buffer_to_file(const char *path, const char *buffer) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(buffer, f);
    fclose(f);
    return 0;
}

void ensure_certs_dir() {
    struct stat st = {0};
    // Crea la cartella base se manca
    if (stat(CLIENT_STORAGE_DIR, &st) == -1) {
        mkdir(CLIENT_STORAGE_DIR, 0700);
    }
    // Crea la sottocartella certs
    if (stat(CLIENT_CERTS_DIR, &st) == -1) {
        mkdir(CLIENT_CERTS_DIR, 0700);
    }
}
int client_service_has_ca() {
    // Il Service conosce il percorso perché usa le definizioni di pki.h
    return (access("client_storage/certs/ca.crt", F_OK) == 0);
}
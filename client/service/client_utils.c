#include "client_utils.h"
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
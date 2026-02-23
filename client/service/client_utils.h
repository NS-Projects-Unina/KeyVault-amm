#ifndef CLIENT_UTILS_H
#define CLIENT_UTILS_H

#include <stddef.h>

// Definiamo i percorsi isolati (coerenti con pki.c)
#define CLIENT_STORAGE_DIR "client_storage"
#define CLIENT_CERTS_DIR   "client_storage/certs/"

const char* get_system_user();
int load_file_to_buffer(const char *path, char *buffer, size_t size);
int save_buffer_to_file(const char *path, const char *buffer);


void ensure_certs_dir();
#endif


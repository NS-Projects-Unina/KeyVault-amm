#ifndef CLIENT_UTILS_H
#define CLIENT_UTILS_H

#include <stddef.h>

const char* get_system_user();
int load_file_to_buffer(const char *path, char *buffer, size_t size);
int save_buffer_to_file(const char *path, const char *buffer);

#endif


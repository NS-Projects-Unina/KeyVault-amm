#include "client_context.h"
#include <string.h>

static char global_server_ip[64] = "127.0.0.1"; // Default
static int global_server_port = 8080;          // Default

void client_context_set_server_ip(const char *ip) {
    if (ip && strlen(ip) > 0) {
        strncpy(global_server_ip, ip, sizeof(global_server_ip) - 1);
    }
}

const char* client_context_get_server_ip() {
    return global_server_ip;
}

void client_context_set_server_port(int port) {
    global_server_port = port;
}

int client_context_get_server_port() {
    return global_server_port;
}
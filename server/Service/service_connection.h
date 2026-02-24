#ifndef SERVICE_CONNECTION_H
#define SERVICE_CONNECTION_H

#include <openssl/ssl.h>
#include <stddef.h>

int service_init_system();
void service_shutdown();
int service_accept_client(char *out_fp, size_t fp_len, char *out_user, size_t user_len, SSL **out_ssl);
void service_close_client(SSL *ssl);
int service_read_data(SSL *ssl, char *buffer, int max_len);
int service_send_data(SSL *ssl, const char *data);

#endif
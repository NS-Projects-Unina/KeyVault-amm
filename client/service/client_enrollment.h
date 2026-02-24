#ifndef CLIENT_ENROLLMENT_H
#define CLIENT_ENROLLMENT_H

#include <stddef.h>

int client_service_needs_enrollment();
int client_service_request_enrollment(const char *user);

// Nuove funzioni atomiche per l'orchestrazione del Controller
int client_enrollment_generate_csr(const char *user);
int client_enrollment_send_and_save_cert(const char *user, const char *otp);
void client_enrollment_cleanup_csr(const char *user);

#endif // CLIENT_ENROLLMENT_H
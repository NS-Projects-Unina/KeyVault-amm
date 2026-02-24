#ifndef SERVICE_ENROLLMENT_H
#define SERVICE_ENROLLMENT_H
#include <openssl/ssl.h>

int service_request_enrollment(const char *user, const char *otp);
int service_process_enrollment(SSL *ssl, const char *user, const char *otp, const char *csr_content);

#endif
#ifndef CLIENT_ENROLLMENT_H
#define CLIENT_ENROLLMENT_H

int client_service_needs_enrollment();
int client_service_request_enrollment(const char *user);
int client_service_perform_enrollment(const char *user, const char *otp);

#endif
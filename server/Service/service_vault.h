#ifndef SERVICE_VAULT_H
#define SERVICE_VAULT_H

int service_save_credential(const char *fp, const char *svc, const char *blob);
char *service_get_all(const char *fp);

#endif
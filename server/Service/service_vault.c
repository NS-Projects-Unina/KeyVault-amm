#include "service_vault.h"
#include "dal.h"

int service_save_credential(const char *fp, const char *svc, const char *blob) {
    return dal_save_record(fp, svc, blob);
}

char *service_get_all(const char *fp) {
    return dal_fetch_all_records(fp);
}
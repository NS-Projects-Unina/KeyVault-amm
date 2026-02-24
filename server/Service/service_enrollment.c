#include "service_enrollment.h"
#include "service_connection.h"
#include "dal.h"
#include "pki.h"
#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

int service_request_enrollment(const char *user, const char *otp) {
    return dal_save_pending_request(user, otp);
}

int service_process_enrollment(SSL *ssl, const char *user, const char *otp, const char *csr_content) {
    if (dal_verify_and_burn_otp(user, otp) != 0) {
        service_send_data(ssl, "ERROR|OTP errato o scaduto");
        return -1;
    }

    BIO *bio = BIO_new_mem_buf(csr_content, -1);
    X509_REQ *csr = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!csr) { service_send_data(ssl, "ERROR|CSR malformata"); return -1; }

    char fingerprint[65];
    if (get_csr_fingerprint(csr, fingerprint, sizeof(fingerprint)) != 0) {
        X509_REQ_free(csr); return -1;
    }
    X509_REQ_free(csr);

    if (dal_fingerprint_exists(fingerprint) || dal_username_taken(user)) {
        service_send_data(ssl, "ERROR|Credenziali già in uso");
        return -1;
    }

    char csr_path[256], cert_path[256];
    snprintf(csr_path,  sizeof(csr_path),  SERVER_CERTS_PATH "%s.csr", fingerprint);
    snprintf(cert_path, sizeof(cert_path), SERVER_CERTS_PATH "%s.crt", fingerprint);

    FILE *f = fopen(csr_path, "w");
    if (f) { fputs(csr_content, f); fclose(f); }

    if (pki_sign_client_request(fingerprint) != 0) {
        service_send_data(ssl, "ERROR|Errore interno della PKI"); return -1;
    }

    if (dal_register_user(fingerprint, user) != 0) {
        service_send_data(ssl, "ERROR|Errore database"); return -1;
    }

    FILE *fc = fopen(cert_path, "r");
    if (!fc) return -1;
    char cert_buf[4096];
    size_t n = fread(cert_buf, 1, sizeof(cert_buf) - 1, fc);
    cert_buf[n] = '\0';
    fclose(fc);

    return (service_send_data(ssl, cert_buf) > 0) ? 0 : -1;
}
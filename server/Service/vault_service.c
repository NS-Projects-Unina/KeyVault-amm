#include "vault_service.h"
#include "ssl.h"
#include "network.h"
#include "pki.h"
#include "dal.h"
#include "system_context.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/pem.h>



/* ========================================================================= *
 *                  CICLO DI VITA DEL SISTEMA                                *
 * ========================================================================= */

int vault_service_init_system() {
    setup_server_infrastructure();
    init_openssl();

    // Creiamo le risorse temporaneamente
    SSL_CTX *ctx = create_server_ctx("certs/server.crt", "certs/server.key", "certs/ca.crt");
    int fd = create_tcp_socket();
    
    if (bind_socket(fd, 8080) < 0) return -1;
    listen_socket(fd, 128);

    // Salviamo tutto nel layer Context
    sys_ctx_set(ctx, fd); 
    
    return 0;
}

void vault_service_shutdown() {
    SystemContext *ctx = sys_ctx_get();
    if (ctx->server_ctx) { SSL_CTX_free(ctx->server_ctx); ctx->server_ctx = NULL; }
    if (ctx->listen_fd != -1) { close_socket(ctx->listen_fd); ctx->listen_fd = -1; }
    cleanup_openssl();
}


/* ========================================================================= *
 *                          ACCETTAZIONE CLIENT                              *
 * ========================================================================= */

/*
 * Accetta una connessione in ingresso, esegue l'handshake TLS e identifica il client.
 * Restituisce l'SSL* attivo tramite out_ssl: ogni thread avrà il suo oggetto SSL*.
 * Il chiamante deve chiamare vault_service_close_client(ssl) quando ha finito.
 */
int vault_service_accept_client(char *out_fp, size_t fp_len,
                                char *out_user, size_t user_len,
                                SSL **out_ssl){

    // **out_ssl serve per restituire al chiamante l'oggetto SSL* creato per questa connessione.
    // con *out_ssl si accede al contenuto del puntatore.
    *out_ssl = NULL; //Inizialmente nullo.
    SystemContext *sys = sys_ctx_get();
    
    int client_fd = accept_client(sys->listen_fd); //Chiamata bloccante.
    if (client_fd < 0) return -1;

    // Elevazione a TLS
    SSL *ssl = accept_tls_connection(sys->server_ctx, client_fd); 
    // ssl -> oggetto TLS in memoria
    if (!ssl) {
        close_socket(client_fd);
        return -1;
    }

    int res = get_client_full_identity(ssl, out_user, user_len, out_fp, fp_len);

    if (res == 1) {
        printf("[+] Service: Connessione mTLS stabilita.\n");
        printf("[*] User: %s | FP: %.16s...\n", out_user, out_fp);
    } else if (res == 0) {
        printf("[!] Service: Connessione anonima (Fase Enrollment).\n");
    } else {
        printf("[-] Service: Errore durante l'identificazione del client.\n");
        vault_service_close_client(ssl);
        return -1;
    }

    *out_ssl = ssl;
    return res;
}

void vault_service_close_client(SSL *ssl) {
    if (!ssl) return;
    int fd = SSL_get_fd(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    if (fd != -1) close_socket(fd);
}


/* ========================================================================= *
 * I/O DI RETE (thread-safe: ogni chiamata opera sul proprio SSL*)           *
 * ========================================================================= */

int vault_service_read_data(SSL *ssl, char *buffer, int max_len) {
    if (!ssl) return -1;
    return SSL_read(ssl, buffer, max_len);
}

int vault_service_send_data(SSL *ssl, const char *data) {
    if (!ssl || !data) return -1;
    return SSL_write(ssl, data, strlen(data));
}


/* ========================================================================= *
 * LOGICA DI ENROLLMENT                                                      *
 * ========================================================================= */

int vault_service_request_enrollment(const char *user, const char *otp) {
    return dal_save_pending_request(user, otp);
}

int vault_service_process_enrollment(SSL *ssl, const char *user,
                                     const char *otp, const char *csr_content)
{
    // 1. Validazione OTP
    if (dal_verify_and_burn_otp(user, otp) != 0) {
        vault_service_send_data(ssl, "ERROR|OTP errato o scaduto");
        return -1;
    }

    // 2. Parsing della CSR PEM
    BIO *bio = BIO_new_mem_buf(csr_content, -1);
    X509_REQ *csr = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!csr) {
        vault_service_send_data(ssl, "ERROR|CSR malformata o illeggibile");
        return -1;
    }

    // 3. Calcolo del fingerprint della chiave pubblica
    char fingerprint[65];
    if (get_csr_fingerprint(csr, fingerprint, sizeof(fingerprint)) != 0) {
        X509_REQ_free(csr);
        return -1;
    }
    X509_REQ_free(csr);

    // 4. Controlli di sicurezza nel database
    if (dal_fingerprint_exists(fingerprint)) {
        vault_service_send_data(ssl, "ERROR|Chiave già registrata");
        return -1;
    }
    if (dal_username_taken(user)) {
        vault_service_send_data(ssl, "ERROR|Username occupato");
        return -1;
    }

    // 5. Salvataggio CSR e firma da parte della PKI
    char csr_path[256], cert_path[256];
    snprintf(csr_path,  sizeof(csr_path),  "certs/%s.csr", fingerprint);
    snprintf(cert_path, sizeof(cert_path), "certs/%s.crt", fingerprint);

    FILE *f = fopen(csr_path, "w");
    if (!f) return -1;
    fputs(csr_content, f);
    fclose(f);

    if (pki_sign_client_request(fingerprint) != 0) {
        vault_service_send_data(ssl, "ERROR|Errore interno della PKI");
        return -1;
    }

    // 6. Registrazione nel database
    if (dal_register_user(fingerprint, user) != 0) {
        vault_service_send_data(ssl, "ERROR|Errore salvataggio database");
        return -1;
    }

    // 7. Invio del certificato firmato al client
    FILE *fc = fopen(cert_path, "r");
    if (!fc) return -1;
    char cert_buf[4096];
    size_t n = fread(cert_buf, 1, sizeof(cert_buf) - 1, fc);
    cert_buf[n] = '\0';
    fclose(fc);

    printf("[+] Service: Enroll completato per user '%s' con FP %.16s...\n",
           user, fingerprint);

    if (vault_service_send_data(ssl, cert_buf) <= 0) return -1;
    return 0;
}


/* ========================================================================= *
 * LOGICA DI BUSINESS (VAULT)                                                *
 * ========================================================================= */

int vault_service_save_credential(const char *fp, const char *svc, const char *blob) {
    return dal_save_record(fp, svc, blob);
}

char *vault_service_get_all(const char *fp) {
    return dal_fetch_all_records(fp);
}
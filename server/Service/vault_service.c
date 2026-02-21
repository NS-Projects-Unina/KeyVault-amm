#include "vault_service.h"
#include "ssl.h"
#include "network.h"
#include "pki.h"
#include "dal.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/pem.h> //Per la gestione dei certificati in memoria

// Lo stato dell'infrastruttura di rete è blindato qui dentro
static SSL_CTX *server_ctx = NULL;
static int listen_fd = -1;

// Manteniamo traccia del client attualmente connesso
static SSL *current_client_ssl = NULL;


// Inizializzazione con il nuovo contesto Ibrido
int vault_service_init_system() {
    setup_server_infrastructure();
    init_openssl();
    // Usiamo la funzione aggiornata in ssl.c che permette l'accesso anonimo
    server_ctx = create_server_ctx("certs/server.crt", "certs/server.key", "certs/ca.crt");
    if (!server_ctx) return -1;

    listen_fd = create_tcp_socket();
    if (bind_socket(listen_fd, 8080) < 0) return -1;
    listen_socket(listen_fd, 5);
    return 0;
}

/*
 * Accetta un client e determina il tipo di connessione.
 * Riempie out_fp (Fingerprint) e out_user (Username/CN).
 * return 1 se mTLS, 0 se TLS Semplice, -1 errore.
 */
int vault_service_accept_client(char *out_fp, size_t fp_len, char *out_user, size_t user_len) {
    int client_fd = accept_client(listen_fd);
    if (client_fd < 0) return -1;

    // Tenta l'handshake TLS
    current_client_ssl = accept_tls_connection(server_ctx, client_fd);
    if (!current_client_ssl) {
        close_socket(client_fd);
        return -1;
    }

    int res = get_client_full_identity(current_client_ssl, out_user, user_len, out_fp, fp_len);
    
    if (res == 1) {
        printf("[+] Service: Connessione mTLS stabilita.\n");
        printf("[*] User: %s | FP: %.16s...\n", out_user, out_fp);
    } else if (res == 0) {
        printf("[!] Service: Connessione anonima (Fase Enrollment).\n");
    } else{ 
        printf("[-] Service: Errore durante l'identificazione del client.\n");
        vault_service_close_client();
    }

    return res; 
}

// --- LOGICA DI ENROLLMENT ---

int vault_service_process_enrollment(const char *user, const char *otp, const char *csr_content) {
    
    // 1. Validazione OTP
    if (dal_verify_and_burn_otp(user, otp) != 0) {
        vault_service_send_data("ERROR|OTP errato o scaduto");
        return -1;
    }

    //2. Elaborazione CSR
    //Il client ha mandato la CSR come stringa PEM, ma il server deve convertirla in un oggetto che OpenSSL capisce
    BIO *bio = BIO_new_mem_buf(csr_content, -1); //Astrazione di I/O di OpenSSL, per leggere dalla memoria
    X509_REQ *csr = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL); //// Trasformiamo quel buffer in una struttura X509_REQ (la vera CSR crittografica)
    BIO_free(bio);

    if (!csr) {
        vault_service_send_data("ERROR|CSR malformata o illeggibile");
        return -1;
    }

    // Usiamo l'utility get_csr_fingerprint per scavare nella CSR e fare l'hash della Public Key, 
    //così da ottenere un identificatore univoco (Fingerprint)
    char fingerprint[65];
    if (get_csr_fingerprint(csr, fingerprint, sizeof(fingerprint)) != 0) {
        X509_REQ_free(csr);
        return -1;
    }
    X509_REQ_free(csr);

    // 3. --- CONTROLLI DI SICUREZZA NEL DATABASE ---
    // A. Questa chiave è già registrata?
    if (dal_fingerprint_exists(fingerprint)) {
        vault_service_send_data("ERROR|Chiave già stata registrata");
        return -1;
    }

    // B. Questo username è già stato preso da un'altra chiave?
    if (dal_username_taken(user)) { //Evitiamo caos nel database
        vault_service_send_data("ERROR|Username occupato");
        return -1;
    }

    // 4. Se i controlli passano, salviamo la CSR temporaneamente e firmiamo
    // Usiamo il FINGERPRINT come nome file per evitare collisioni 
    char csr_path[256], cert_path[256];
    snprintf(csr_path, sizeof(csr_path), "certs/%s.csr", fingerprint);
    snprintf(cert_path, sizeof(cert_path), "certs/%s.crt", fingerprint);

    FILE *f = fopen(csr_path, "w");
    if (!f) return -1;
    fputs(csr_content, f);
    fclose(f);

    //Chiamiamo la PKI per firmare, CA userà la ca.key per generare il .crt
    if (pki_sign_client_request(fingerprint) != 0) { 
        //Passo fingerprint come identificatore per il file in cui è salvata la CSR (fingerprint.csr)
        vault_service_send_data("ERROR|Errore interno della PKI");
        return -1;
    }

    // 5. REGISTRAZIONE NEL DATABASE
    // Colleghiamo ufficialmente Fingerprint <-> Username
    if (dal_register_user(fingerprint, user) != 0) {
        vault_service_send_data("ERROR|Errore salvataggio database");
        return -1;
    }

    // 6. Invio del certificato al client
    FILE *fc = fopen(cert_path, "r"); //Apriamo il certificato appena creato per leggerne il contenuto e inviarlo al client
    if (!fc) return -1;
    char cert_buf[4096];
    size_t n = fread(cert_buf, 1, sizeof(cert_buf)-1, fc);
    cert_buf[n] = '\0';
    fclose(fc);

    return vault_service_send_data(cert_buf);
}

int vault_service_save_credential(const char *user, const char *svc, const char *blob) {
    return dal_save_record(user, svc, blob);
}

char* vault_service_get_all(const char *user) {
    return dal_get_records_by_user(user);
}

int vault_service_read_data(char *buffer, int max_len) {
    if (!current_client_ssl) return -1;
    return SSL_read(current_client_ssl, buffer, max_len);
}

int vault_service_send_data(const char *data) {
    if (!current_client_ssl || !data) return -1;
    return SSL_write(current_client_ssl, data, strlen(data));
}

void vault_service_close_client() {
    if (current_client_ssl) {
        int fd = SSL_get_fd(current_client_ssl);
        SSL_shutdown(current_client_ssl);
        SSL_free(current_client_ssl);
        if (fd != -1) close_socket(fd);
        current_client_ssl = NULL;
    }
}

void vault_service_shutdown() {
    if (server_ctx) SSL_CTX_free(server_ctx);
    if (listen_fd != -1) close_socket(listen_fd);
    cleanup_openssl();
}
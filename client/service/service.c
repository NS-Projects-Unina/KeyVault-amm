#include "service.h"
#include "ssl.h"
#include "network.h"
#include "pki.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

static SSL *active_ssl = NULL;
static int active_sockfd = -1;

// --- HELPER INTERNI ---

static const char* get_system_user() {
    struct passwd *pw = getpwuid(getuid());
    return (pw) ? pw->pw_name : "default_user";
}

// Legge un file (es. CSR) e lo carica in una stringa per l'invio
static int load_file_to_buffer(const char *path, char *buffer, size_t size) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(buffer, 1, size - 1, f);
    buffer[n] = '\0';
    fclose(f);
    return 0;
}

// Salva una stringa (es. certificato ricevuto) in un file locale
static int save_buffer_to_file(const char *path, const char *buffer) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(buffer, f);
    fclose(f);
    return 0;
}

// --- LOGICA DI ENROLLMENT (CHIAMATA DAL CONTROLLER) ---
int client_service_needs_enrollment() {
    char cert_path[256];
    snprintf(cert_path, sizeof(cert_path), "certs/%s.crt", get_system_user());
    // Se il file .crt non esiste, dobbiamo registrarci
    return (access(cert_path, F_OK) == -1);
}


//Da modificare e togliere la parte di SSL grezza
int client_service_perform_enrollment(const char *reg_pass) {
    const char *user = get_system_user(); 
    //Valuteremo se cambiare questa funzione per accettare un username specifico, ma per ora ci affidiamo all'utente di sistema.
    char csr_path[256], cert_path[256], csr_buf[4096], response[4096];

    snprintf(csr_path, sizeof(csr_path), "certs/%s.csr", user);
    snprintf(cert_path, sizeof(cert_path), "certs/%s.crt", user);

    // 1. PKI: Genera chiave privata-pubblica e CSR localmente
    if (pki_generate_csr(user) != 0) return -1;

    // 2. Leggi la CSR per spedirla
    if (load_file_to_buffer(csr_path, csr_buf, sizeof(csr_buf)) != 0) return -1;

    // 3. Connessione temporanea (TLS base, senza certificato client)
    init_openssl();
    SSL_CTX *tmp_ctx = create_client_basic_ctx("certs/ca.crt"); // Nessun cert/key passato
    int tmp_fd = create_tcp_socket();
    if (connect_to_server(tmp_fd, "127.0.0.1", 8080) < 0) return -1;
    SSL *tmp_ssl = connect_tls_to_server(tmp_ctx, tmp_fd);
    if (!tmp_ssl) return -1;

    // 4. Protocollo: ENROLL|user|pass|CSR_CONTENT
    char command[8192];
    snprintf(command, sizeof(command), "ENROLL|%s|%s|%s", user, reg_pass, csr_buf);
    SSL_write(tmp_ssl, command, strlen(command));
    printf("[*][Service] CSR inviata al server, in attesa di risposta...\n");


    // 5. Ricezione del certificato firmato
    memset(response, 0, sizeof(response));
    int bytes = SSL_read(tmp_ssl, response, sizeof(response) - 1);
    
    if (bytes > 0 && strstr(response, "BEGIN CERTIFICATE")) {
        save_buffer_to_file(cert_path, response);
        printf("[+] Certificato ricevuto e salvato.\n");
    } else {
        fprintf(stderr, "[-] Il server ha rifiutato l'enrollment: %s\n", response);
        SSL_free(tmp_ssl);
        return -1;
    }

    // Pulizia sessione temporanea
    SSL_shutdown(tmp_ssl);
    SSL_free(tmp_ssl);
    SSL_CTX_free(tmp_ctx);
    close(tmp_fd);
    return 0;
}

// --- LOGICA OPERATIVA (mTLS) ---

int client_service_init_session() {
    const char *username = get_system_user();
    char cert_path[256], key_path[256];
    
    snprintf(cert_path, sizeof(cert_path), "certs/%s.crt", username);
    snprintf(key_path, sizeof(key_path), "certs/%s.key", username);

    init_openssl(); //Forse non c'è bisogno di inizializzare OpenSSL due volte (qui e nell'enrollment), ma per sicurezza lo facciamo sempre prima di creare un contesto SSL.
    SSL_CTX *ctx = create_client_mtls_ctx(cert_path, key_path, "certs/ca.crt");
    if (!ctx) return -1;
    
    active_sockfd = create_tcp_socket();
    if (connect_to_server(active_sockfd, "127.0.0.1", 8080) < 0) return -1;

    active_ssl = connect_tls_to_server(ctx, active_sockfd);
    SSL_CTX_free(ctx); 

    return (active_ssl != NULL) ? 0 : -1;
}



void client_service_store_data(const char *service_name, const char *password) {
    if (!active_ssl) return;
    char command[1024], response[1024];
    snprintf(command, sizeof(command), "STORE|%s|%s", service_name, password);

    if (SSL_write(active_ssl, command, strlen(command)) <= 0) {
        fprintf(stderr, "[-] Errore di comunicazione col server.\n");
        return;
    }
    memset(response, 0, sizeof(response));
    if (SSL_read(active_ssl, response, sizeof(response) - 1) > 0) {
        printf("[SERVER]: %s\n", response);
    }
}

void client_service_fetch_data() {
    if (!active_ssl) return;
    char *command = "GET_ALL";
    char response[4096];

    printf("[*] Recupero dati dal vault...\n");
    if (SSL_write(active_ssl, command, strlen(command)) <= 0) return;

    memset(response, 0, sizeof(response));
    if (SSL_read(active_ssl, response, sizeof(response) - 1) > 0) {
        printf("\n=== IL TUO VAULT ===\n%s\n====================\n", response);
    } else {
        printf("[-] Nessun dato ricevuto.\n");
    }
}

void client_service_close_session() {
    if (active_ssl) {
        SSL_shutdown(active_ssl);
        SSL_free(active_ssl);
        active_ssl = NULL;
    }
    if (active_sockfd != -1) {
        close(active_sockfd); 
        active_sockfd = -1;
    }
    cleanup_openssl();
    printf("[*] Sessione terminata e risorse liberate.\n");
}
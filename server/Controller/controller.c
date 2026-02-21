#include "controller.h"
#include "vault_service.h" // Assicurati di includere l'header corretto del Service
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Helper per l'invio: il Controller prepara la stringa e dice al Service "spediscila"
static void send_response(const char *status, const char *message) {
    char final_resp[4096];
    snprintf(final_resp, sizeof(final_resp), "%s|%s", status, message);
    vault_service_send_data(final_resp); 
}

/* ========================================================================= *
 * GESTIONE SESSIONE ANONIMA (Solo per Registrazione)                        *
 * ========================================================================= */
static void handle_enrollment_session() {
    char buffer[1024]; 
    int bytes = vault_service_read_data(buffer, sizeof(buffer) - 1);
    if (bytes <= 0) return;
    buffer[bytes] = '\0'; 

    char *cmd = strtok(buffer, "|");
    
    // FASE 1: Richiesta OTP
    if (cmd && strcmp(cmd, "REQUEST_ENROLL") == 0) {
        char *user = strtok(NULL, "|");
        if (user) {
            char otp[9]; 
            generate_random_otp(otp, sizeof(otp));
            
            // Il Controller ora parla solo col Service!
            if (vault_service_request_enrollment(user, otp) == 0) {
                printf("\n[!!!] ADMIN: Richiesta da '%s'. OTP generato: %s\n", user, otp);
                send_response("OK", "Richiesta registrata. Chiedi l'OTP all'admin.");
            } else {
                send_response("ERROR", "Impossibile processare la richiesta.");
            }
        }
    }
    // FASE 2: Invio CSR + OTP
    else if (cmd && strcmp(cmd, "ENROLL") == 0) {
        char *user = strtok(NULL, "|");
        char *otp = strtok(NULL, "|");
        char *csr = strtok(NULL, ""); 

        if (user && otp && csr) {
            if (vault_service_process_enrollment(user, otp, csr) != 0) {
                // L'errore è già inviato dentro process_enrollment
                printf("[-] Enrollment fallito per l'utente %s.\n", user);
            }
        }
    }
    else {
        send_response("ERROR", "In questa fase puoi solo registrarti.");
    }
}

/* ========================================================================= *
 * GESTIONE SESSIONE AUTENTICATA (mTLS - Accesso al Vault)                   *
 * ========================================================================= */
static void handle_authenticated_session(const char *fingerprint, const char *username) {
    char buffer[2048]; 
    
    // Loggiamo lo username per l'admin, ma usiamo il fingerprint per il Vault
    printf("[+] Controller: Sessione attiva per l'utente: %s [ID: %.8s...]\n", username, fingerprint);

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int bytes = vault_service_read_data(buffer, sizeof(buffer) - 1);
        if (bytes <= 0) break; 

        // BUG FIX: Terminazione stringa manuale
        buffer[bytes] = '\0'; 

        char *temp_buf = strdup(buffer);
        char *cmd = strtok(temp_buf, "|");
        if (!cmd) { free(temp_buf); continue; }

        if (strcmp(cmd, "STORE") == 0) {
            char *svc_name = strtok(NULL, "|");
            char *payload = strtok(NULL, "|");

            //  Passiamo il FINGERPRINT al Service, non più lo username
            if (svc_name && payload) {
                if (vault_service_save_credential(fingerprint, svc_name, payload) == 0)
                    send_response("OK", "Credenziale salvata nel vault univoco");
                else
                    send_response("ERROR", "Errore di persistenza dati");
            }
        } 
        else if (strcmp(cmd, "GET_ALL") == 0) {
            // NOTA: Recupero dati tramite FINGERPRINT
            char *data = vault_service_get_all(fingerprint);
            
            if (data && data[0] != '\0') {
                vault_service_send_data(data);
                free(data);
            } else {
                send_response("INFO", "Il tuo vault è vuoto");
                if (data) free(data);
            }
        }
       
        free(temp_buf);
    }
}
/* ========================================================================= *
 *                  LOOP PRINCIPALE DEL SERVER                               *
 * ========================================================================= */
int run_server_controller() {
    printf("[*] Inizializzazione moduli di sistema...\n");

    if (vault_service_init_system() != 0) { 
        fprintf(stderr, "[-] Errore: Impossibile avviare il Service.\n");
        return -1;
    }

    char fingerprint[65]; // Hash SHA-256
    char username[256];    // Nome dal certificato
    printf("[+] Server pronto. In attesa di client in modalità Ibrida...\n");
    

    while (1) {
        memset(fingerprint, 0, sizeof(fingerprint));
        memset(username, 0, sizeof(username));
        
        // Il Service accetta un client e determina se è autenticato (mTLS) o anonimo (TLS semplice)
        int auth_status = vault_service_accept_client(fingerprint, sizeof(fingerprint), username, sizeof(username));
        
        if (auth_status == 1) {
            // Passiamo entrambi alla sessione
            handle_authenticated_session(fingerprint, username);
        } 
        else if (auth_status == 0) {
            handle_enrollment_session();
        }
        vault_service_close_client();
    }
    vault_service_shutdown();
    return 0;
}
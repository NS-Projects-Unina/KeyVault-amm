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
    char buffer[8192]; // Buffer capiente per contenere la CSR
    
    printf("[*] Controller: Connessione anonima, in attesa del comando ENROLL...\n");

    int bytes = vault_service_read_data(buffer, sizeof(buffer) - 1);
    if (bytes <= 0) return; // Client disconnesso senza dire nulla

    char *temp_buf = strdup(buffer);
    char *cmd = strtok(temp_buf, "|");

    if (cmd && strcmp(cmd, "ENROLL") == 0) {
        char *user = strtok(NULL, "|");
        char *pass = strtok(NULL, "|");
        // Passando la stringa vuota "", strtok prende tutto il resto (che è la CSR)
        char *csr = strtok(NULL, ""); 

        if (user && pass && csr) {
            printf("[*] Controller: Richiesta di Enrollment ricevuta per l'utente: %s\n", user);
            
            // Il Service si occupa di validare la password, salvare il file e firmarlo
            if (vault_service_process_enrollment(user, pass, csr) == 0) {
                printf("[+] Controller: Certificato generato e inviato a %s.\n", user);
            } else {
                printf("[-] Controller: Registrazione fallita per %s.\n", user);
            }
        } else {
            printf("[-] Controller: Comando ENROLL malformato.\n");
            send_response("ERROR", "Parametri di registrazione mancanti o malformati");
        }
    } else {
        send_response("ERROR", "Accesso negato. Usa il comando ENROLL per registrarti.");
    }

    free(temp_buf);
}

/* ========================================================================= *
 * GESTIONE SESSIONE AUTENTICATA (mTLS - Accesso al Vault)                   *
 * ========================================================================= */
static void handle_authenticated_session(const char *identity) {
    char buffer[2048]; 
    
    printf("[+] Controller: Sessione attiva per l'utente certificato: %s\n", identity);

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        
        // Lettura dati criptati dal client astratta dal Service
        int bytes = vault_service_read_data(buffer, sizeof(buffer) - 1);
        if (bytes <= 0) break; // Client disconnesso

        printf("[*] Controller: Ricevuto comando da %s: %s\n", identity, buffer);

        char *temp_buf = strdup(buffer);
        char *cmd = strtok(temp_buf, "|");

        if (!cmd) {
            send_response("ERROR", "Protocollo malformato");
            free(temp_buf);
            continue;
        }

        if (strcmp(cmd, "STORE") == 0) {
            char *svc_name = strtok(NULL, "|");
            char *payload = strtok(NULL, "|");

            if (svc_name && payload) {
                if (vault_service_save_credential(identity, svc_name, payload) == 0)
                    send_response("OK", "Credenziale salvata nel vault");
                else
                    send_response("ERROR", "Errore di persistenza dati");
            } else {
                send_response("ERROR", "Parametri STORE mancanti");
            }
        } 
        else if (strcmp(cmd, "GET_ALL") == 0) {
            char *data = vault_service_get_all(identity);
            
            if (data && data[0] != '\0') {
                vault_service_send_data(data); // Invio dati grezzi
                free(data);
            } else {
                send_response("INFO", "Il tuo vault è vuoto");
                if (data) free(data);
            }
        }
        else {
            send_response("ERROR", "Comando sconosciuto o non autorizzato");
        }

        free(temp_buf);
    }
    printf("[*] Controller: Sessione terminata per %s\n", identity);
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

    printf("[+] Server pronto. In attesa di client in modalità Ibrida...\n");
    char identity[256];

    while (1) {
        memset(identity, 0, sizeof(identity)); // Pulisce il buffer ad ogni iterazione
        
        // Il Service accetta la connessione e ci dice il livello di sicurezza
        int auth_status = vault_service_accept_client(identity, sizeof(identity));
        
        if (auth_status == 1) {
            // [CASO 1] Il client ha un certificato valido
            handle_authenticated_session(identity);
        } 
        else if (auth_status == 0) {
            // [CASO 2] Il client si è connesso in TLS Semplice
            handle_enrollment_session();
        } 
        else {
            // [CASO -1] Errore di rete o di handshake
            fprintf(stderr, "[-] Connessione fallita o rifiutata.\n");
        }

        // Il Controller ordina la chiusura, il Service esegue la disconnessione sicura
        vault_service_close_client(); 
    }

    vault_service_shutdown();
    return 0;
}
#include "controller.h"
#include "service.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Helper per l'invio: il Controller prepara la stringa e dice al Service "spediscila"
static void send_response(const char *status, const char *message) {
    char final_resp[4096];
    snprintf(final_resp, sizeof(final_resp), "%s|%s", status, message);
    vault_service_send_data(final_resp); 
}

static void handle_client_session(const char *identity) {
    char buffer[2048];
    printf("[+] Controller: Sessione attiva per l'utente: %s\n", identity);

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        
        // Lettura astratta: non c'è più SSL_read qui!
        int bytes = vault_service_read_data(buffer, sizeof(buffer) - 1);
        if (bytes <= 0) break; // Client disconnesso

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
                    send_response("OK", "Credenziale salvata");
                else
                    send_response("ERROR", "Errore di persistenza");
            }
        } 

        free(temp_buf);
    }
    printf("[*] Controller: Sessione terminata per %s\n", identity);
}

int run_server_controller() {
    printf("[*] Inizializzazione moduli di sistema...\n");

    if (vault_service_init_system() != 0) {
        fprintf(stderr, "[-] Errore: Impossibile avviare il Service.\n");
        return -1;
    }

    printf("[+] Server pronto. In attesa di client...\n");
    char identity[256];

    while (1) {
        // Il Service accetta il client, fa il mTLS e ci passa SOLO chi è l'utente
        if (vault_service_accept_client(identity, sizeof(identity)) == 0) { //Bloccante finché non arriva un client
            handle_client_session(identity);
            
            // Il Controller ordina la chiusura, ma è il Service che smonta la socket
            vault_service_close_client(); 
        }
    }

    vault_service_shutdown();
    return 0;
}
#include "controller.h"
#include "service_connection.h"
#include "service_enrollment.h"
#include "service_vault.h"
#include "service_utility.h" // Per generate_random_otp
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

/* ========================================================================= *
 * STRUTTURA DATI PASSATA AD OGNI THREAD                        *
 * ========================================================================= *
 * Raggruppa tutto il contesto di una singola connessione.
 * Viene allocata sull'heap prima della creazione del thread e liberata
 * dal thread stesso al termine, così il main loop non deve aspettare.
*/

typedef struct {
    SSL  *ssl; // Puntatore all'oggetto SSL specifico per quel Client
    int   auth_status; // -1 = errore, 0 = sessione anonima (enrollment), 1 = sessione autenticata (mTLS)
    char  fingerprint[65]; // Impronta del certificato client (se autenticato)
    char  username[256]; // Nome utente associato al certificato (se autenticato) o alla richiesta di enrollment
} ClientContext;

/* ========================================================================= *
 * HELPER I/O (ora thread-safe: usano il proprio ssl)               *
 * ========================================================================= */

static void send_response(SSL *ssl, const char *status, const char *message) {
    char final_resp[4096];
    snprintf(final_resp, sizeof(final_resp), "%s|%s", status, message);
    service_send_data(ssl, final_resp);
}

/* ========================================================================= *
 * GESTIONE SESSIONE ANONIMA (Solo per Registrazione)                        *
 * ========================================================================= */

static void handle_enrollment_session(SSL *ssl) {
    char buffer[1024];
    int bytes = service_read_data(ssl, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) return;
    buffer[bytes] = '\0';

    char *cmd = strtok(buffer, "|");

    // FASE 1: Richiesta OTP
    if (cmd && strcmp(cmd, "REQUEST_ENROLL") == 0) {
        char *user = strtok(NULL, "|");
        if (user) {
            char otp[9]; // Buffer per l'OTP
            
            // Il Service di enrollment gestisce la generazione e il salvataggio
            if (service_request_enrollment(user, otp) == 0) {
                printf("\n[!!!] ADMIN: Richiesta da '%s'. OTP generato: %s\n", user, otp);
                send_response(ssl, "OK", "Richiesta registrata. Chiedi l'OTP all'admin.");
            } else {
                send_response(ssl, "ERROR", "Impossibile processare la richiesta.");
            }
        }
    }
    // FASE 2: Invio CSR + OTP
    else if (cmd && strcmp(cmd, "ENROLL") == 0) {
        char *user = strtok(NULL, "|");
        char *otp  = strtok(NULL, "|");
        char *csr  = strtok(NULL, "");

        if (user && otp && csr) {
            if (service_process_enrollment(ssl, user, otp, csr) != 0) {
                printf("[-] Enrollment fallito per l'utente %s.\n", user);
            }
        }
    }
    else {
        send_response(ssl, "ERROR", "In questa fase puoi solo registrarti.");
    }
}


/* ========================================================================= *
 * GESTIONE SESSIONE AUTENTICATA (mTLS)                                      *
 * ========================================================================= */

static void handle_authenticated_session(SSL *ssl,
                                         const char *fingerprint,
                                         const char *username)
{
    char buffer[2048];

    printf("[+] Controller: Sessione attiva per l'utente: %s [ID: %.8s...]\n",
           username, fingerprint);

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int bytes = service_read_data(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) break;

        buffer[bytes] = '\0';

        char *temp_buf = strdup(buffer);
        char *cmd      = strtok(temp_buf, "|");
        if (!cmd) { free(temp_buf); continue; }

        if (strcmp(cmd, "STORE") == 0) {
            char *svc_name = strtok(NULL, "|");
            char *payload  = strtok(NULL, "|");

            if (svc_name && payload) {
                if (service_save_credential(fingerprint, svc_name, payload) == 0)
                    send_response(ssl, "OK", "Credenziale salvata nel vault univoco");
                else
                    send_response(ssl, "ERROR", "Errore di persistenza dati");
            }
        }
        else if (strcmp(cmd, "GET_ALL") == 0) {
            char *data = service_get_all(fingerprint);

            if (data && data[0] != '\0') {
                service_send_data(ssl, data);
                free(data);
            } else {
                send_response(ssl, "INFO", "Il tuo vault è vuoto");
                if (data) free(data);
            }
        }

        free(temp_buf);
    }
}


/* ========================================================================= *
 * ENTRY-POINT DEL THREAD                                                    *
 * ========================================================================= */

/*
 * Ogni connessione viene gestita da qui in poi in modo completamente
 * indipendente. Il thread libera il ClientContext e chiude la connessione
 * prima di uscire: il main loop non deve fare join().
 */
static void *client_thread(void *arg) {
    /* Detachiamo subito il thread: le risorse vengono rilasciate
     * automaticamente alla sua terminazione, senza bisogno di join(). */
    pthread_detach(pthread_self());

    ClientContext *ctx = (ClientContext *)arg;

    if (ctx->auth_status == 1) {
        handle_authenticated_session(ctx->ssl, ctx->fingerprint, ctx->username);
    } else if (ctx->auth_status == 0) {
        handle_enrollment_session(ctx->ssl);
    }

    service_close_client(ctx->ssl);
    free(ctx);
    return NULL;
}


/* ========================================================================= *
 * LOOP PRINCIPALE DEL SERVER                           *
 * ========================================================================= */

int run_server_controller() {
    printf("[*] Inizializzazione moduli di sistema...\n");

    // Inizializza PKI e socket di ascolto.
    if (service_init_system() != 0) {
        fprintf(stderr, "[-] Errore: Impossibile avviare il Service.\n");
        return -1;
    }

    printf("[+] Server pronto. In attesa di client (modalità multi-thread)...\n");

    while (1) { //Loop di ascolto.
        
        //Ogni thread ha bisogno del suo spazio di memoria dedicato Heap
        ClientContext *ctx = calloc(1, sizeof(ClientContext));
        // calloc(numElem,size), inizializza a zero e torna un puntatore al blocco di memoria allocato.

        if (!ctx) {
            fprintf(stderr, "[-] Memoria esaurita, impossibile accettare client.\n");
            continue;
        }

        // Chiamata bloccante: il Main loop attende che arrivi qualcuno
        ctx->auth_status = service_accept_client(
            ctx->fingerprint, sizeof(ctx->fingerprint),
            ctx->username,    sizeof(ctx->username),
            &ctx->ssl
        ); 
        // ctx è l'indirizzo della struttura nell'heap.
        // ctx -> ssl è il contenuto del campo SSL.
        // & ctx-> ssl è l'indirizzo dove risiede il campo SSL all'interno della struttura.
        // In questo modo la funzione service_accept_client può scrivere l'indirizzo della struttura SSL* creata per il client direttamente dentro ctx->ssl, così che il thread possa usarla per comunicare con quel client specifico.

        if (ctx->auth_status < 0) {
            /* Errore di rete/TLS: scartiamo questo client e riproviamo. */
            free(ctx);
            continue;
        }
        printf("[*] Nuovo client accettato. Auth status: %d\n", ctx->auth_status);  
        /* Creiamo un thread per gestire questo client e torniamo subito
         * ad accettare la prossima connessione. */
        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, ctx) != 0) {
            perror("[-] pthread_create");
            service_close_client(ctx->ssl);
            free(ctx);
        }
    }

    service_shutdown();
    return 0;
}
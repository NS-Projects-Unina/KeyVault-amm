#include "controller.h"
#include "service.h"
#include <stdio.h>
#include <stdlib.h>

// Funzione helper interna (non esposta nell'header)
static void dispatch_service_action(int choice) {
    char service_name[128], password[128];

    switch (choice) {
        case 1:
            printf("\nServizio (es. Amazon): "); 
            scanf("%127s", service_name);
            printf("Password: "); 
            scanf("%127s", password);
            // Il Controller non invia byte grezzi, delega al Service
            client_service_store_data(service_name, password);
            break;
        default:
            printf("[-] Opzione non valida.\n");
    }
}

void start_app_controller() {
    printf("[*] Verifica stato identità digitale...\n");

    // --- FASE 0: BOOTSTRAP / ENROLLMENT ---
    // Il Controller del Client chiede al Service se mancano i certificati locali
    if (client_service_needs_enrollment()) {
        printf("[!] Nessun certificato trovato per questo utente.\n");
        printf("[*] Avvio procedura di registrazione (Enrollment)...\n");

        char reg_password[128];
        printf("Inserisci la Password di Registrazione: ");
        // Pulizia buffer e lettura password
        if (scanf("%127s", reg_password) != 1) return;

        // Ordiniamo al Service di generare la CSR e scambiarla col Server
        if (client_service_perform_enrollment(reg_password) != 0) {
            fprintf(stderr, "[-] Errore: Registrazione fallita. Impossibile ottenere il certificato.\n");
            return;
        }
        printf("[+] Registrazione completata con successo! Certificato salvato.\n");
    }

    // --- FASE 1: INIZIALIZZAZIONE SESSIONE mTLS ---
    // Ora siamo certi che il certificato esista (o era già lì o lo abbiamo appena creato)
    if (client_service_init_session() != 0) {
        fprintf(stderr, "[-] Errore fatale: Impossibile stabilire la connessione mTLS.\n");
        return;
    }

    printf("[+] Connessione mTLS stabilita con successo!\n");

    // --- FASE 2: LOOP DELL'INTERFACCIA UTENTE ---
    int choice;
    while (1) {
        printf("\n--- MENU VAULT ---\n");
        printf("1. Salva nuova password\n");
        printf("2. Recupera il tuo Vault\n"); // Aggiunto per completezza
        printf("3. Esci\n");
        printf("Scelta: ");
        
        if (scanf("%d", &choice) != 1) break;

        if (choice == 3) {
            printf("[*] Chiusura sessione in corso...\n");
            break;
        }

        dispatch_service_action(choice);
    }

    // --- FASE 3: CLEANUP ---
    client_service_close_session();
}
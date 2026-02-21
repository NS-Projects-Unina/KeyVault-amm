#include "controller.h"
#include "service.h"
#include <stdio.h>
#include <stdlib.h>

// Funzione helper interna (non esposta nell'header)
static void dispatch_service_action(int choice) {
    char service_name[128], password[128];

    switch (choice) {
        case 1: // STORE
            printf("\n--- SALVATAGGIO CREDENZIALE ---\n");
            printf("Servizio (es. Amazon): "); 
            scanf("%127s", service_name);
            printf("Password: "); 
            scanf("%127s", password);
            
            // Chiamata al Service
            client_service_store_data(service_name, password);
            break;

        case 2: // GET_ALL
            printf("\n--- RECUPERO VAULT PERSONALE ---\n");
            // Questa funzione nel Service dovrà inviare "GET_ALL" al server
            client_service_fetch_data(); 
            break;

        default:
            printf("[-] Opzione non valida.\n");
    }
}
void start_app_controller() {
    
    printf("[*] Verifica stato identità digitale...\n");

    if (client_service_needs_enrollment()) {
        printf("[!] Nessun certificato trovato.\n");
        const char *user = get_system_user();

        // 1. Fase di Richiesta: Il server genera l'OTP
        printf("[*] Invio richiesta di accreditamento per: %s\n", user);
        if (client_service_request_enrollment(user) != 0) {
            fprintf(stderr, "[-] Errore nella richiesta iniziale.\n");
            return;
        }

        printf("\n----------------------------------------------------------\n");
        printf("[?] Richiesta registrata! Ora contatta l'Amministratore.\n");
        printf("[?] Fatti dare l'OTP per completare l'enrollment.\n");
        printf("----------------------------------------------------------\n");

        // 2. Fase di Finalizzazione: L'utente inserisce l'OTP
        char otp[64];
        printf("\nInserisci l'OTP fornito dall'admin: ");
        if (scanf("%63s", otp) != 1) return;

        if (client_service_perform_enrollment(user, otp) != 0) {
            fprintf(stderr, "[-] Registrazione fallita. OTP errato o scaduto.\n");
            return;
        }
        printf("[+] Registrazione completata! Certificato ottenuto.\n");
    } else {
        printf("[+] Certificato digitale già presente. Procedo con la connessione mTLS.\n");
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
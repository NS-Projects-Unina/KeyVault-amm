#include "controller.h"
#include "client_service.h"    // Per sessione mTLS e Vault
#include "client_enrollment.h" // Per la fase di registrazione
#include "client_utils.h"      // Per get_system_user
#include "crypto_utils.h"       // Per la gestione chiavi e cifratura
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void dispatch_service_action(int choice) {
    char service_name[128], password[128];

    // CANCELLATO: unsigned char final_key[AES_KEY_LEN]; -> Non serve più qui

    switch (choice) {
        case 1: // STORE
            // CANCELLATO: if (client_service_prepare_crypto_key(final_key) != 0) -> Lo facciamo nel bootstrap
            printf("\n--- SALVATAGGIO CREDENZIALE ---\n");
            printf("Servizio: "); scanf("%127s", service_name);
            printf("Password: "); scanf("%127s", password);
            
            // MODIFICATO: Non passiamo più la chiave, il service usa quella di sessione
            client_service_store_data_encrypted(service_name, password);
            break;

        case 2: // GET_ALL
            // CANCELLATO: if (client_service_prepare_crypto_key(final_key) != 0) -> Ridondante
            printf("\n--- RECUPERO VAULT PERSONALE ---\n");
            
            // MODIFICATO: Nessun parametro passato
            client_service_fetch_data_encrypted(); 
            break;

        default:
            printf("[-] Opzione non valida.\n");
    }
}

void start_app_controller() {
    // 1. Fase di Bootstrap / Enrollment (Invariata)
    if (client_service_needs_enrollment()) {
        const char *user = get_system_user();
        if (client_service_request_enrollment(user) != 0) return;

        char otp[64];
        printf("\nInserisci l'OTP fornito dall'admin: ");
        scanf("%63s", otp);

        if (client_service_perform_enrollment(user, otp) != 0) return;
    }

    // 2. Inizializzazione sessione mTLS operativa
    if (client_service_init_session() != 0) {
        fprintf(stderr, "[-] Errore fatale: Impossibile connettersi.\n");
        return;
    }
    printf("[+] Connessione mTLS stabilita con successo!\n");

    // 3. SBLOCCO CRITTOGRAFICO (BOOTSTRAP)
    // Questa è l'unica volta in cui l'utente interagisce con la chiave!
    printf("\n[*] Inizializzazione sicurezza Vault...\n");
    if (client_service_bootstrap_crypto() != 0) {
        fprintf(stderr, "[-] Sblocco fallito. Uscita.\n");
        client_service_close_session();
        return;
    }

    // 4. Loop Interfaccia Utente
    int choice;
    while (1) {
        printf("\n--- MENU VAULT (SBLOCCATO) ---\n");
        printf("1. Salva nuova password\n");
        printf("2. Recupera il tuo Vault\n");
        printf("3. Esci\n");
        printf("Scelta: ");
        
        if (scanf("%d", &choice) != 1) break;
        if (choice == 3) break;

        dispatch_service_action(choice);
    }

    client_service_close_session();
}
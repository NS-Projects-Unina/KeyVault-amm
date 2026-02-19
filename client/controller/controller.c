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
    printf("[*] Inizializzazione sessione sicura in corso...\n");

    // 1. Chiediamo al Service di preparare tutto (Certificati, Socket, mTLS)
    if (client_service_init_session() != 0) {
        fprintf(stderr, "[-] Errore fatale: Impossibile stabilire la connessione col server.\n");
        return;
    }

    printf("[+] Connessione stabilita con successo!\n");

    // 2. Loop dell'interfaccia utente
    int choice;
    while (1) {
        printf("\n--- MENU VAULT ---\n");
        printf("1. Salva nuova password\n");
        printf("3. Esci\n");
        printf("Scelta: ");
        
        if (scanf("%d", &choice) != 1) break;

        if (choice == 3) {
            printf("[*] Chiusura in corso...\n");
            break;
        }

        dispatch_service_action(choice);
    }

    // 3. Chiusura pulita tramite il Service
    client_service_close_session();
}
#include "controller.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("=== [KEY-VAULT SERVER BOOT] ===\n");

    // Passiamo il controllo al Controller, che avvierà l'intero sistema
    if (run_server_controller() != 0) {
        fprintf(stderr, "[-] Chiusura anomala del server.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
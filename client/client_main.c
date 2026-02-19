#include "controller.h"
#include <stdio.h>

int main() {
    printf("=== KEY-VAULT CLIENT (Zero-Knowledge Mode) ===\n");

    // Passiamo subito il controllo al Controller che avvierà l'app
    start_app_controller(); 

    return 0;
}
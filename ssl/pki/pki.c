#include "pki.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h> 

void init_pki_directory() {
    struct stat st = {0};
    if (stat("certs", &st) == -1) { 
        printf("[*] Creazione directory 'certs/' per la PKI...\n");
        mkdir("certs", 0700);
    }
}

void setup_server_infrastructure() {
    init_pki_directory();
    if (access("certs/ca.crt", F_OK) != -1) {
        printf("[+] Infrastruttura PKI Server già presente. Avvio...\n");
        return;
    }

    printf("[!] Prima esecuzione: Generazione Root CA e identità Server...\n");

    system("openssl req -x509 -newkey rsa:4096 -keyout certs/ca.key -out certs/ca.crt -days 365 -nodes -subj '/CN=KeyVault Root CA' 2>/dev/null");
    system("openssl genrsa -out certs/server.key 2048 2>/dev/null");
    system("openssl req -new -key certs/server.key -out certs/server.csr -subj '/CN=KeyVault Server' 2>/dev/null");
    system("openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/server.crt -days 365 2>/dev/null");

    system("rm -f certs/*.csr");
    printf("[+] Infrastruttura Server completata con successo!\n");
}

/* ========================================================================= *
 * NUOVA FUNZIONE: Firma la CSR del Client                                   *
 * ========================================================================= */
int pki_sign_client_request(const char *username) {
    char command[512];

    // Verifica che il server possieda la chiave privata della CA
    if (access("certs/ca.key", F_OK) == -1) {
        fprintf(stderr, "[-] Errore Fatale: Root CA non trovata sul server.\n");
        return -1;
    }

    printf("[*] PKI: Ricevuta richiesta CSR. Avvio procedura di firma per '%s'...\n", username);

    // Firma la CSR usando ca.crt e ca.key
    snprintf(command, sizeof(command), 
             "openssl x509 -req -in certs/%s.csr -CA certs/ca.crt -CAkey certs/ca.key "
             "-CAcreateserial -out certs/%s.crt -days 365 2>/dev/null", 
             username, username);
    
    int res = system(command);

    // Pulizia: la CSR del client non ci serve più sul server una volta firmata
    snprintf(command, sizeof(command), "rm -f certs/%s.csr", username);
    system(command);

    if (res == 0) {
        printf("[+] PKI: Certificato '%s.crt' generato e firmato con successo!\n", username);
        return 0;
    } else {
        fprintf(stderr, "[-] PKI: Errore durante la generazione del certificato.\n");
        return -1;
    }
}

int pki_generate_csr(const char *username) {
    char command[512];
    init_pki_directory();

    //Genera chiave privata RSA a 2048 bit e salva in certs/username.key
    snprintf(command, sizeof(command), "openssl genrsa -out certs/%s.key 2048 2>/dev/null", username); //2>dev/null serve a nascondere i log OpenSSL
    system(command);

    //Attiviamo il modulo di OpenSSL dedicato alla gestione delle X.509 Certificate Signing Request
    snprintf(command, sizeof(command), 
             "openssl req -new -key certs/%s.key -out certs/%s.csr -subj '/CN=%s' 2>/dev/null", 
             username, username, username);
    /*
        -new -> new request da 0
        -key certs/%s.key, dice a Open SSL di firmare la richiesta con la chiave privata, così da autenticare il client
        -out certs/%s.csr -> output della CSR in un file
        -subj -> specifica i campi del subject della CSR, solo CN (Common Name).
    */

    return system(command);
}
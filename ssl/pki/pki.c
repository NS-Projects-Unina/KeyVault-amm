#include "pki.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h> 

void init_pki_directory() {
    struct stat st = {0};
    // Creiamo la struttura a due livelli: server_storage/certs/
    if (stat(SERVER_BASE_DIR, &st) == -1) {
        mkdir(SERVER_BASE_DIR, 0700);
    }

    if (stat(SERVER_CERTS_PATH, &st) == -1) { 
        printf("[*] Creazione directory privata server: '%s'\n", SERVER_CERTS_PATH);
        mkdir(SERVER_CERTS_PATH, 0700);
    }
}

void setup_server_infrastructure() {
    init_pki_directory();
    
    // Controllo esistenza nella cartella privata
    if (access(SERVER_CERTS_PATH "ca.crt", F_OK) != -1) {
        printf("[+] Infrastruttura PKI Server presente in %s. Avvio...\n", SERVER_CERTS_PATH);
        return;
    }

    printf("[!] Prima esecuzione: Generazione Root CA e identità Server in storage isolato...\n");

    // 1. Generazione Root CA (Certificato + Chiave Privata)
    system("openssl req -x509 -newkey rsa:4096 "
           "-keyout " SERVER_CERTS_PATH "ca.key "
           "-out " SERVER_CERTS_PATH "ca.crt "
           "-days 365 -nodes -subj '/CN=KeyVault Root CA' 2>/dev/null");

/*
        -509: indica che stiamo creando un certificato per una Root CA, non una semplice richiesta
        -newkey rsa:4096, genera una chiave RSA a 4096 bit
        -nodes: la chiave privata ca.key non è protetta da password, per cui un attaccante accede al 
        filesystem e potrebbe firmare qualsiasi certificato a nome della nostra CA
        -subj: imposta il Common Name a KeyVault Root CA
*/

    // 2. Generazione Chiave Privata del Server
    system("openssl genrsa -out " SERVER_CERTS_PATH "server.key 2048 2>/dev/null");

    // 3. Generazione CSR per il Server
    system("openssl req -new -key " SERVER_CERTS_PATH "server.key "
           "-out " SERVER_CERTS_PATH "server.csr -subj '/CN=KeyVault Server' 2>/dev/null");

    // 4. Firma del certificato Server tramite la propria CA
    system("openssl x509 -req -in " SERVER_CERTS_PATH "server.csr "
           "-CA " SERVER_CERTS_PATH "ca.crt -CAkey " SERVER_CERTS_PATH "ca.key "
           "-CAcreateserial -out " SERVER_CERTS_PATH "server.crt -days 365 2>/dev/null");
    /*
        x509 utility per la gestione certificati nello standard X.509.
        -req comunica a OpenSSL che il file in INPUT è una CSR
        -in server.csr specifica il file di input (CSR effettiva)
        -CA ca.crt indica il certificato della ROOT CA
        
        -CAkey ca.key indica la chiave privata della key privata della CA
        Solo chi possiede questa chiave può emettere certificati validi per l'infrastruttura
        
        -CAcreateserial: ordina a OpenSSL di creare un file che tiene traccia
        del numero di serie dei certificati, così che ogni certificato abbia un numero univoco
        
        -out server.crt, definisce il file di output che verrà usato dal server
        per presentarsi ai client durante l'handshake TLS

        -days 365: data scadenza certificato
    */


    // Pulizia dei file temporanei nella cartella privata
    system("rm -f " SERVER_CERTS_PATH "*.csr");
    printf("[+] Infrastruttura Server completata con successo in: %s\n", SERVER_CERTS_PATH);
}


int pki_sign_client_request(const char *identifier) {
    char command[1024];

    // Il server cerca la CA nella sua cartella privata
    if (access(SERVER_CERTS_PATH "ca.key", F_OK) == -1) {
        fprintf(stderr, "[-] Errore Fatale: Root CA non trovata in %s.\n", SERVER_CERTS_PATH);
        return -1;
    }

    printf("[*] PKI: Avvio procedura di firma per '%s' usando CA in %s...\n", identifier, SERVER_CERTS_PATH);
    
    // Firma la CSR (che il server ha ricevuto e salvato temporaneamente nello storage)
    // usando il certificato ca.crt e la chiave della CA del server ca.key
    snprintf(command, sizeof(command), 
             "openssl x509 -req -in " SERVER_CERTS_PATH "%s.csr "
             "-CA " SERVER_CERTS_PATH "ca.crt -CAkey " SERVER_CERTS_PATH "ca.key "
             "-CAcreateserial -out " SERVER_CERTS_PATH "%s.crt -days 365 2>/dev/null", 
             identifier, identifier);
    
    int res = system(command);

    // Pulizia della CSR temporanea sul server
    snprintf(command, sizeof(command), "rm -f " SERVER_CERTS_PATH "%s.csr", identifier);
    system(command);

    if (res == 0) {
        printf("[+] PKI: Certificato '" SERVER_CERTS_PATH "%s.crt' generato con successo!\n", identifier);
        return 0;
    } else {
        fprintf(stderr, "[-] PKI: Errore durante la generazione del certificato.\n");
        return -1;
    }
}

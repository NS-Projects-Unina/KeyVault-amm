#include "pki.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h> 
//Ci permette di leggere lo stato dei file e delle cartelle, ad esempio per verificare se un file esiste o se una directory è presente.


//Assicuriamoci che esista la cartella certs/ prima di portela usare
void init_pki_directory() {
    struct stat st = {0}; //Struttura in cui ci saranno informazioni sul file o directory
    //Ogni file ha un inode del filesystem, che contiene i metadati.

    if (stat("certs", &st) == -1) { 
//Con questa funzione chiediamo al SO se esiste la cartella certs/ e otteniamo i suoi metadati. 
//Se il risultato è -1, significa che la cartella non esiste.
        printf("[*] Creazione directory 'certs/' per la PKI...\n");
        mkdir("certs", 0700);
    }

}

void setup_server_infrastructure() {

    init_pki_directory();
    //Se non mettessi sto return, ogni volta che avvio il server, mi ricreerebbe la CA e il certificato del server, 
    //sovrascrivendo quelli esistenti.
    if (access("certs/ca.crt", F_OK) != -1) {
        printf("[+] Infrastruttura PKI Server già presente. Avvio...\n");
        return;
    }

    printf("[!] Prima esecuzione: Generazione Root CA e identità Server...\n");

    // 1. Root CA
    system("openssl req -x509 -newkey rsa:4096 -keyout certs/ca.key -out certs/ca.crt -days 365 -nodes -subj '/CN=KeyVault Root CA' 2>/dev/null");

    // 2. Server Cert
    system("openssl genrsa -out certs/server.key 2048 2>/dev/null");
    system("openssl req -new -key certs/server.key -out certs/server.csr -subj '/CN=KeyVault Server' 2>/dev/null");
    system("openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/server.crt -days 365 2>/dev/null");

    // Pulizia
    system("rm -f certs/*.csr");
    printf("[+] Infrastruttura Server completata con successo!\n");
}

int generate_client_certificate(const char *username) {
    char command[512];
    init_pki_directory();

    if (access("certs/ca.crt", F_OK) == -1) {
        printf("[-] Errore: Root CA non trovata. \n");
        return -1;
    }

    // Controlla se l'utente ha già un certificato
    snprintf(command, sizeof(command), "certs/%s.crt", username);
    if (access(command, F_OK) != -1) {
        printf("[*] Il certificato per '%s' esiste già.\n", username);
        return 0;
    }

    printf("[*] Generazione certificato per l'utente: %s...\n", username);

    // Generazione Chiave e CSR
    snprintf(command, sizeof(command), "openssl genrsa -out certs/%s.key 2048 2>/dev/null", username);
    system(command);
    snprintf(command, sizeof(command), "openssl req -new -key certs/%s.key -out certs/%s.csr -subj '/CN=KeyVault Client - %s' 2>/dev/null", username, username, username);
    system(command);

    // Firma con la Root CA
    snprintf(command, sizeof(command), "openssl x509 -req -in certs/%s.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/%s.crt -days 365 2>/dev/null", username, username);
    system(command);

    // Pulizia CSR
    snprintf(command, sizeof(command), "rm -f certs/%s.csr", username);
    system(command);

    printf("[+] Certificato '%s.crt' generato con successo!\n", username);
    return 0;
}
#include <stdio.h> // Standard I/O library 
#include <stdlib.h> // Standard library for memory allocation and process control
#include <string.h> // String handling library
#include <unistd.h> // POSIX API for Unix-based systems


//Per le primitive di rete (socket, bind, listen, accept) e le strutture dati (sockaddr_in)  
#include <sys/socket.h> // Socket definitions
#include <arpa/inet.h> // Definitions for internet operations
#include "network.h" // Include the header file for network functions


// ==========================================
//              FUNZIONI COMUNI
// ==========================================
int create_tcp_socket() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[-] Errore in socket()");
        return -1;
    }
    return sockfd;
}

void close_socket(int sockfd){
// Evitiamo di chiudere socket non valide (fd negativi)
    if (sockfd >= 0) {
        if (close(sockfd) < 0) {
            perror("[-] Errore durante la chiusura della socket");
        } else {
            printf("[*] Socket (fd: %d) chiusa correttamente.\n", sockfd);
        }
    } else {
        printf("[-] Attenzione: tentativo di chiudere una socket non valida (fd: %d).\n", sockfd);
    }
}

// ==========================================
//             FUNZIONI LATO SERVER
// ==========================================

int bind_socket(int sockfd, int port) {
    struct sockaddr_in server_addr;
   
    server_addr.sin_family = AF_INET; // IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY; // Ascolta su tutte le interfacce
    server_addr.sin_port = htons(port); // Porta in network byte order

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[-] Errore in bind()");
        return -1;
    }

    /* Perchè c'è il cast (struct sockaddr *)&server_addr? 
       La funzione bind() accetta un puntatore a struct sockaddr, ma noi stiamo usando struct sockaddr_in per specificare l'indirizzo del server. 
       Il cast è necessario per convertire il puntatore da struct sockaddr_in* a struct sockaddr* in modo che sia compatibile con la firma della funzione bind(). 
       Questo è un uso comune nelle programmazioni di socket in C, poiché struct sockaddr è una struttura generica che può rappresentare diversi tipi di indirizzi (IPv4, IPv6, ecc.), mentre struct sockaddr_in è specifica per IPv4.
    */
    return 0;
}

int listen_socket(int sockfd, int backlog) {

    if(backlog <= 0 || backlog > 100) {// Controllo di validità del backlog
        backlog = 5; // Valore di default se backlog non è positivo
        printf("[*] Backlog non specificato o non valido, impostato a default: %d\n", backlog);
    }

    if (listen(sockfd, backlog) < 0) {
        perror("[-] Errore in listen()");
        return -1;
    }
    return 0;
}

int accept_client(int sockfd) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr); // Variabile per memorizzare la lunghezza dell'indirizzo del client
    int client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &addr_len);
    if (client_sockfd < 0) {
        perror("[-] Errore in accept()");
        return -1;
    }
    printf("[+] Nuovo client connesso: %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    return client_sockfd;
}

// ==========================================
//              FUNZIONI LATO CLIENT
// ==========================================

int connect_to_server(int sockfd, const char *ip, int port) {
    struct sockaddr_in server_addr;

    // 1. Pulizia della memoria (FONDAMENTALE!)
    memset(&server_addr, 0, sizeof(server_addr));
    
    // 2. Preparazione delle coordinate del server
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // inet_pton (Presentation to Network): Converte la stringa IP in binario
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("[-] Indirizzo IP non valido o formato non supportato");
        return -1;
    }

    printf("[*] Iniziando il Three-Way Handshake verso %s:%d...\n", ip, port);

    // 3. Connessione attiva (Connect)
    // Usiamo 'sockfd' normale, senza asterisco
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[-] Errore durante la connect()");
        return -1;
    }

    printf("[+] Connessione TCP stabilita con successo!\n");
    return 0; // Successo
}
#include "network.h" // Includi l'header con le funzioni di rete
#include <stdio.h>   // Input/Output standard

int main() {
    printf("Starting client...\n");

    // 1. Creazione della socket del client
    int client_socket_fd = create_tcp_socket(); 
    if (client_socket_fd < 0) {
        fprintf(stderr, "Failed to create client socket\n");
        return 1;
    }

    // 2. Connessione al Server
    printf("Attempting to connect to server at 127.0.0.1:8080...\n");
    
    // Funzione della  libreria per avviare il Three-Way Handshake
    int connect_result = connect_to_server(client_socket_fd, "127.0.0.1", 8080);
    
    if (connect_result < 0) {
        fprintf(stderr, "Failed to connect to the server\n");
        close_socket(client_socket_fd); // Chiudiamo in caso di errore
        return 1;
    }

    printf("Connected to server successfully!\n");
    while(1){
        
    }
    return 0;
}
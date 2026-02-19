#include "network.h" // Include the header file for network functions
#include <stdio.h>   // Include standard input/output library


int main(){
    printf("Starting server...\n");
    printf("=======================================\n");
    printf("    KEY-VAULT: TEST PKI (SERVER)       \n");
    printf("=======================================\n");

    printf("[*] Avvio procedura di auto-provisioning...\n");
    
    // Crea la cartella certs/, la CA e il certificato del server
    setup_server_infrastructure();

    printf("\n[+] Test PKI Server completato!\n");
    printf("[*] Controlla la cartella 'certs/' per vedere i file generati.\n");

    int server_socket_fd = create_tcp_socket(); // Create a server socket on port
    
    if (server_socket_fd < 0) {
        fprintf(stderr, "Failed to create server socket\n");
        return 1;
    }

    int bind_result = bind_socket(server_socket_fd, 8080);
    if (bind_result < 0) {
        fprintf(stderr, "Failed to bind to port 8080\n");
        close_socket(server_socket_fd);
        return 1;
    }

    int backlog;
    printf("Enter backlog value (number of pending connections): ");
    scanf("%d", &backlog);
    int listen_result = listen_socket(server_socket_fd, backlog);
    if (listen_result < 0) {
        fprintf(stderr, "Failed to listen on port 8080\n");
        close_socket(server_socket_fd);
        return 1;
    }
    printf("Server is listening on port 8080...\n");
    
    int client_socket_fd = accept_client(server_socket_fd);
    if (client_socket_fd < 0) {
        fprintf(stderr, "Failed to accept client connection\n");
        close_socket(server_socket_fd);
        return 1;
    }
    printf("Client connected successfully!\n");
    while(1){

    }
    return 0;

}
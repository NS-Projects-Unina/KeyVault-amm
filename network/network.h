// LAYER 1: Network-related functions and definitions

#ifndef NETWORK_H
#define NETWORK_H


// ==========================================
//              FUNZIONI COMUNI
// ==========================================

// Creates a generic TCP socket 
int create_tcp_socket();

// Closes a socket given its file descriptor
void close_socket(int sockfd);


// ==========================================
//             FUNZIONI LATO SERVER
// ==========================================

// Binds the socket to the specified port 
int bind_socket(int sockfd, int port);

// Start listening for incoming connections with a specified backlog
int listen_socket(int sockfd, int backlog);

// Accepts an incoming client connection and returns a new socket file descriptor for communication
int accept_client(int sockfd);

// ==========================================
//              FUNZIONI LATO CLIENT
// ==========================================

// Connects to the server at the specified IP address and port, returning a socket file descriptor for communication
int connect_to_server(int sockfd, const char *ip, int port);
#endif // NETWORK_H
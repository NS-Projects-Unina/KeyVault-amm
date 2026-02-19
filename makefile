CC = gcc
# Aggiungiamo tutti i nuovi path di inclusione per gli header (.h)
CFLAGS = -Wall -Wextra -g \
         -I./network \
         -I./ssl \
         -I./ssl/pki \
         -I./server/Controller \
         -I./server/Service \
         -I./server/Dal \
         -I./client/controller \
         -I./client/service

LDFLAGS = -lssl -lcrypto 

all: server_app client_app

# Compilazione del SERVER
# Includiamo tutti i file .c dei layer del server
server_app: server/server_main.c \
            network/network.c \
            ssl/ssl.c \
            ssl/pki/pki.c \
            server/Controller/controller.c \
            server/Service/vault_service.c \
            server/Dal/dal.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Compilazione del CLIENT
# Includiamo tutti i file .c dei layer del client
client_app: client/client_main.c \
            network/network.c \
            ssl/ssl.c \
            ssl/pki/pki.c \
            client/controller/controller.c \
            client/service/service.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f server_app client_app
	rm -rf certs/
	rm -f vault.dat
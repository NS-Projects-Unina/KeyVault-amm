
CC = gcc
# Aggiornati i percorsi di inclusione (-I) per trovare tutti i file .h
CFLAGS = -Wall -Wextra -g -I./network -I./ssl -I./ssl/pki

all: server_app client_app

# Regola per costruire il Server (ora pesca pki.c da ssl/pki/)
server_app: server/server_main.c network/network.c ssl/pki/pki.c
	$(CC) $(CFLAGS) server/server_main.c network/network.c  ssl/pki/pki.c -o server_app 

# Regola per costruire il Client (ora pesca pki.c da ssl/pki/)
client_app: client/client_main.c network/network.c ssl/pki/pki.c
	$(CC) $(CFLAGS) client/client_main.c network/network.c ssl/pki/pki.c -o client_app 

clean:
	rm -f server_app client_app
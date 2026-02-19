CC = gcc
CFLAGS = -Wall -Wextra -g -I./network -I./ssl -I./ssl/pki
LDFLAGS = -lssl -lcrypto 

all: server_app client_app

# Nota come $(LDFLAGS) sia alla fine!
server_app: server/server_main.c network/network.c ssl/ssl.c ssl/pki/pki.c
	$(CC) $(CFLAGS) server/server_main.c network/network.c ssl/ssl.c ssl/pki/pki.c -o server_app $(LDFLAGS)

client_app: client/client_main.c network/network.c ssl/ssl.c ssl/pki/pki.c
	$(CC) $(CFLAGS) client/client_main.c network/network.c ssl/ssl.c ssl/pki/pki.c -o client_app $(LDFLAGS)

clean:
	rm -f server_app client_app
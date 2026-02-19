# 1. Variabili di Compilazione
CC = gcc
# Aggiunto -I./network per dire a gcc dove trovare network.h
CFLAGS = -Wall -Wextra -g -I./network

# 2. Obiettivo principale
all: server_app client_app

# 3. Regola per costruire il Server (ora si chiama server_app)
server_app: server/server_main.c network/network.c network/network.h
	$(CC) $(CFLAGS) server/server_main.c network/network.c -o server_app

# 4. Regola per costruire il Client (ora si chiama client_app)
client_app: client/client_main.c network/network.c network/network.h
	$(CC) $(CFLAGS) client/client_main.c network/network.c -o client_app
    
# 5. Regola di pulizia
clean:
	rm -f server_app client_app
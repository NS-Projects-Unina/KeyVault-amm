CC = gcc
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
PORT = 8080

all: server_app client_app

# Compilazione del SERVER
server_app: server/server_main.c \
            network/network.c \
            ssl/ssl.c \
            ssl/pki/pki.c \
            server/Controller/controller.c \
            server/Service/vault_service.c \
            server/Dal/dal.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Compilazione del CLIENT
client_app: client/client_main.c \
            client/controller/controller.c \
            client/service/client_utils.c \
            client/service/client_enrollment.c \
            client/service/client_service.c \
            client/service/crypto_utils.c \
            network/network.c \
            ssl/ssl.c \
            ssl/pki/pki.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# --- TARGET PER FERMARE IL SERVER ---
stop:
	@echo "[*] Liberazione porta $(PORT)..."
	@fuser -k $(PORT)/tcp 2>/dev/null || echo "[-] Nessun processo attivo sulla porta $(PORT)."

clean: stop
	@echo "[*] Pulizia file binari e database..."
	rm -f server_app client_app
	rm -rf certs/
	rm -f pending_requests.dat users.dat
	rm -rf vaults/
	@echo "[+] Sistema resettato e porta libera."
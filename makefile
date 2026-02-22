CC = gcc

# Recuperiamo automaticamente flag e librerie per GTK 4 e OpenSSL
GTK_CFLAGS := $(shell pkg-config --cflags gtk4)
GTK_LIBS   := $(shell pkg-config --libs gtk4)

# CFLAGS: aggiungiamo le flag di GTK e il path del client per trovare gui_manager.h
CFLAGS = -Wall -Wextra -g \
         -I./network \
         -I./ssl \
         -I./ssl/pki \
         -I./server/Controller \
         -I./server/Service \
         -I./server/Dal \
         -I./client/controller \
         -I./client/service \
         -I./client \
         $(GTK_CFLAGS)

# LDFLAGS: SSL, Crypto e ora tutte le librerie grafiche di GTK 4
LDFLAGS = -lssl -lcrypto $(GTK_LIBS)
PORT = 8080

all: server_app client_app

# --- COMPILAZIONE DEL SERVER ---
# Nota: il server non usa GTK, quindi filtriamo LDFLAGS per non appesantirlo
server_app: server/server_main.c \
            network/network.c \
            ssl/ssl.c \
            ssl/pki/pki.c \
            server/Controller/controller.c \
            server/Service/vault_service.c \
            server/Dal/dal.c
	$(CC) $(CFLAGS) $^ -o $@ -lssl -lcrypto


# --- COMPILAZIONE DEL CLIENT (GUI) ---
# RIMOSSO: client/controller/controller.c
client_app: client/client_main.c \
            client/gui_manager/gui_manager.c \
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
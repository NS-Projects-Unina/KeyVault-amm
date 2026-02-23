CC = gcc

# Recuperiamo automaticamente flag e librerie per GTK 4 e OpenSSL
GTK_CFLAGS := $(shell pkg-config --cflags gtk4)
GTK_LIBS   := $(shell pkg-config --libs gtk4)

# CFLAGS: aggiungiamo i nuovi path per trovare gli header nelle sottocartelle
CFLAGS = -Wall -Wextra -g \
         -I./network \
         -I./ssl \
         -I./ssl/pki \
         -I./server/Controller \
         -I./server/Service \
         -I./server/Dal \
         -I./client \
         -I./client/context \
         -I./client/gui_manager \
         -I./client/service \
         $(GTK_CFLAGS)

# LDFLAGS: SSL, Crypto e GTK 4
LDFLAGS = -lssl -lcrypto $(GTK_LIBS)
PORT = 8080

all: server_app client_app

# --- COMPILAZIONE DEL SERVER ---
server_app: server/server_main.c \
            network/network.c \
            ssl/ssl.c \
            ssl/pki/pki.c \
            server/Controller/controller.c \
            server/Service/vault_service.c \
            server/Dal/dal.c
	$(CC) $(CFLAGS) $^ -o $@ -lssl -lcrypto

# --- COMPILAZIONE DEL CLIENT (GUI) ---
# AGGIUNTO: client/context/client_context.c
# NOTA: client_utils.c è già incluso e ora contiene ensure_certs_dir
client_app: client/client_main.c \
            client/context/client_context.c \
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
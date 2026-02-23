CC = gcc

# Recuperiamo flag per GTK 4 e OpenSSL
GTK_CFLAGS := $(shell pkg-config --cflags gtk4)
GTK_LIBS   := $(shell pkg-config --libs gtk4)

# CFLAGS: Aggiunto il path per il nuovo layer Context del server
CFLAGS = -Wall -Wextra -g \
         -I./network \
         -I./ssl \
         -I./ssl/pki \
         -I./server/Controller \
         -I./server/Service \
         -I./server/Dal \
         -I./server/Context \
         -I./client \
         -I./client/context \
         -I./client/gui_manager \
         -I./client/service \
         $(GTK_CFLAGS)

# LDFLAGS: Fondamentale aggiungere -lpthread per i Mutex e i Thread del Controller
LDFLAGS = -lssl -lcrypto -lpthread $(GTK_LIBS)
PORT = 8080

all: server_app client_app

# --- COMPILAZIONE DEL SERVER ---
# Aggiunto server/Context/system_context.c alla lista dei sorgenti
server_app: server/server_main.c \
            network/network.c \
            ssl/ssl.c \
            ssl/pki/pki.c \
            server/Controller/controller.c \
            server/Service/vault_service.c \
            server/Dal/dal.c \
            server/Context/system_context.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# --- COMPILAZIONE DEL CLIENT (GUI) ---
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
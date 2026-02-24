CC = gcc

# Recuperiamo flag per GTK 4 e OpenSSL
GTK_CFLAGS := $(shell pkg-config --cflags gtk4)
GTK_LIBS   := $(shell pkg-config --libs gtk4)

# CFLAGS: Include paths per tutti i moduli del progetto
CFLAGS = -Wall -Wextra -g \
         -I./network \
         -I./ssl \
         -I./ssl/pki \
         -I./server/Controller \
         -I./server/Service \
         -I./server/Dal \
         -I./server/Context \
         -I./client \
         -I./client/controller \
         -I./client/context \
         -I./client/gui_manager \
         -I./client/service \
         $(GTK_CFLAGS)

# LDFLAGS: Librerie di sistema (OpenSSL, Pthread per mutex/thread, e GTK4)
LDFLAGS = -lssl -lcrypto -lpthread $(GTK_LIBS)
PORT = 8080

all: server_app client_app

# --- COMPILAZIONE DEL SERVER ---
# Architettura a servizi disaccoppiati e utility trasversali
server_app: server/server_main.c \
            network/network.c \
            ssl/ssl.c \
            ssl/pki/pki.c \
            server/Controller/controller.c \
            server/Service/service_connection.c \
            server/Service/service_enrollment.c \
            server/Service/service_vault.c \
            server/Service/service_utility.c \
            server/Dal/dal.c \
            server/Context/system_context.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# --- COMPILAZIONE DEL CLIENT (GUI) ---
# Il client non include più pki.c (Separation of Concerns raggiunta)
client_app: client/client_main.c \
            client/controller/client_controller.c \
            client/context/client_context.c \
            client/gui_manager/gui_manager.c \
            client/service/client_utils.c \
            client/service/client_enrollment.c \
            client/service/client_service.c \
            client/service/crypto_utils.c \
            network/network.c \
            ssl/ssl.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# --- TARGET PER FERMARE IL SERVER ---
stop:
	@echo "[*] Liberazione porta $(PORT)..."
	@fuser -k $(PORT)/tcp 2>/dev/null || echo "[-] Nessun processo attivo sulla porta $(PORT)."

# --- TARGET PER RESETTARE L'AMBIENTE (Nuclear Option) ---
clean: stop
	@echo "[*] Pulizia file binari, storage e database..."
	rm -f server_app client_app
	rm -rf server_storage/
	rm -rf client_storage/
	rm -rf vaults/
	rm -f pending_requests.dat pending_requests.tmp users.dat
	rm -f vault.key
	@echo "[+] Sistema resettato completamente."
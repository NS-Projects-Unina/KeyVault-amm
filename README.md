# KeyVault(amm) - Credential Manager Secure

Sistema client-server per la gestione sicura e centralizzata delle credenziali, basato sul paradigma **Zero Trust**.

![Status](https://img.shields.io/badge/status-active-brightgreen) ![Language](https://img.shields.io/badge/language-C-blue)

## 🎯 Cosa Fa

KeyVault(amm) è un vault di credenziali che:
- **Non invia mai password in chiaro** né in rete né su disco
- **Cifra localmente** prima della trasmissione (AES-256-CBC)
- **Verifica identità tramite certificati** X.509 (mTLS)
- **Supporta sblocco multi-fattore**: password o chiave USB
- **Scalabile**: server multithreaded, client snello

Perfetto per ambienti aziendali o domestici dove ti serve un vault privato e veramente tuo.

## 🏗️ Architettura
```
┌─────────────────┐         mTLS (TLS 1.3)        ┌─────────────────┐
│  KeyVault Client│◄──────────────────────────────►│ KeyVault Server │
│  (GTK 4, Linux) │    Certificati X.509           │   (pthreads)    │
│                 │                                │                 │
│ • AES-256-CBC   │                                │ • Root CA       │
│ • Chiavi locali │                                │ • Cert Authority│
│ • Zero-Trust    │                                │ • DAL           │
└─────────────────┘                                └─────────────────┘
```

**Principio cardine:** Zero Trust = la fiducia non è scontata, ma verificata crittograficamente ad ogni passo.

## 📋 Requisiti Principali

### Funzionali
- Configurazione IP del server via GUI
- Importazione del certificato CA fuori banda
- Enrollment con OTP (out-of-band)
- Sblocco sessione: Master Password o USB
- Gestione credenziali (insert, sync, visualizza)

### Non Funzionali
- Autenticazione mTLS (TLS 1.3)
- Cifratura at-rest: AES-256-CBC
- Isolamento dello storage
- Gestione concorrenza: POSIX Threads

## 🔧 Stack Tecnologico

| Componente | Tecnologia |
|-----------|-----------|
| **Linguaggio** | C99 |
| **GUI Client** | GTK 4 + Adwaita |
| **Rete** | OpenSSL (mTLS) |
| **Crittografia** | OpenSSL EVP |
| **Threading** | POSIX Threads (pthreads) |
| **Derivazione chiavi** | PBKDF2 (10k iterazioni) |

## 🚀 Quick Start

### Server
```bash
cd server/
./keyvault_server
# Ascolta sulla porta 8080
# Genera automaticamente la Root CA al primo boot
```

### Client
```bash
cd client/
./keyvault_client
```

**Primo avvio:**
1. Inserisci IP del server (localhost per test)
2. Importa `ca.crt` ricevuto dal server via canale sicuro
3. Completa l'enrollment con OTP dell'admin
4. Scegli Master Password o carica chiave USB
5. 🎉 Vault pronto!

## 🔐 Flusso Operativo

### Enrollment
```
Client                          Server
  │                              │
  ├─── REQUEST_ENROLL ──────────►│
  │                              │ Genera OTP
  │                              ├─ Salva su pending.dat
  │                              │
  │ (Admin consegna OTP OOB)     │
  │                              │
  ├─── ENROLL|OTP|CSR ──────────►│
  │                              ├─ Valida OTP
  │                              ├─ Firma CSR
  │◄──── user.crt ───────────────┤
  │                              │
```

### Vault Operations
```
Client (offline)         Network (mTLS)        Server (remote)
  │                          │                        │
  ├─ Chiave dalla RAM        │                        │
  ├─ AES-256-CBC             │                        │
  ├─ Payload cifrato ───────►│◄── TLS encrypt ──────► │
  │                          │                        ├─ Salva blob
  │                          │◄── TLS decrypt ─────── ┤
  │◄─ Blob cifrato ──────────│                        │
  ├─ Decifratura locale      │                        │
  └─ Password in chiaro      │                        │
```

## 📁 Struttura Progetto
```
keyvault-amm/
├── client/
│   ├── client_controller.c      # Orchestration
│   ├── client_service.c         # Business logic
│   ├── crypto_utils.c           # AES-256-CBC
│   ├── gui_manager.c            # GTK 4 UI
│   └── ...
├── server/
│   ├── controller.c             # Accept loop
│   ├── service_enrollment.c     # OTP + CSR
│   ├── service_vault.c          # STORE/GET
│   ├── dal.c                    # Disk I/O
│   ├── pki.c                    # Root CA
│   └── ...
└── shared/
    ├── ssl.c                    # TLS wrapper
    └── network.c                # BSD sockets
```

### Zero-Persistence

La chiave di sessione viene caricata **solo durante l'operazione** (STORE/GET_ALL) e poi pulita dalla RAM. Niente persistent keying.


##  Note di Sicurezza

- **Non adatto per produzione senza review**: Questo è un progetto didattico/dimostrativo
- **Server in rete privata**: Non esporlo su Internet senza reverse proxy + firewall
- **Master Password robusta**: Almeno 12 caratteri, mista
- **Chiave USB**: Conservala offline in luogo sicuro
- **OTP**: Usa solo canali sicuri (di persona, telefono verificato)

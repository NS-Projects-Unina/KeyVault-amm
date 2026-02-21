#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h>

// --- COSTANTI CRITTOGRAFICHE ---
// AES-256 richiede una chiave di 32 byte (256 bit)
#define AES_KEY_LEN 32  
// L'Initialization Vector per AES-CBC è sempre di 16 byte
#define IV_LEN 16       
// Numero di iterazioni per PBKDF2 (più alto = più sicuro contro il brute-force)
#define ITERATIONS 10000
// Lunghezza del sale per la derivazione della password
#define SALT_LEN 16

// --- GESTIONE CHIAVE FISICA (USB) ---

// Verifica se il file vault.key esiste nel percorso indicato
int crypto_usb_key_exists(const char *path);

// Genera 32 byte casuali e li salva su USB
int crypto_generate_usb_key(const char *path);

// Carica la chiave da 32 byte dalla USB nella memoria RAM (out_key)
int crypto_load_usb_key(const char *path, unsigned char *out_key);


// --- GESTIONE MASTER PASSWORD ---

// Trasforma una password testuale in una chiave AES-256 usando PBKDF2
int crypto_derive_from_password(const char *password, unsigned char *out_key);


// --- OPERAZIONI DI CIFRATURA ---

// Cifra il plaintext e restituisce un blob: [IV (16 byte) + DATI CIFRATI]
int crypto_encrypt(const unsigned char *plaintext, int plaintext_len, 
                   const unsigned char *key, unsigned char *out_buffer);

// Decifra il blob (IV + dati) e restituisce il testo in chiaro
int crypto_decrypt(const unsigned char *ciphertext_blob, int blob_len, 
                   const unsigned char *key, unsigned char *out_plaintext);

#endif
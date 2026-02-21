#include "crypto_utils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// --- GESTIONE CHIAVE FISICA (USB) ---

int crypto_usb_key_exists(const char *path) {
    // access() restituisce 0 se il file è accessibile
    return (access(path, F_OK) == 0);
}

int crypto_generate_usb_key(const char *path) {
    unsigned char key[AES_KEY_LEN];
    
    // Generiamo 32 byte di entropia pura
    if (RAND_bytes(key, sizeof(key)) != 1) {
        return -1;
    }

    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    fwrite(key, 1, sizeof(key), f);
    fclose(f);
    return 0;
}

int crypto_load_usb_key(const char *path, unsigned char *out_key) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    size_t n = fread(out_key, 1, AES_KEY_LEN, f);
    fclose(f);
    
    // Verifichiamo di aver letto esattamente 32 byte
    return (n == AES_KEY_LEN) ? 0 : -1;
}


// --- GESTIONE MASTER PASSWORD ---

int crypto_derive_from_password(const char *password, unsigned char *out_key) {
    // Salt statico per la tesina (in produzione andrebbe generato e salvato)
    const unsigned char salt[] = "KEYVAULT_SALT_2026_AMMODO"; 
    
    // PKCS5_PBKDF2_HMAC: trasforma la password in una chiave robusta
    return PKCS5_PBKDF2_HMAC(password, strlen(password), 
                             salt, sizeof(salt), 
                             ITERATIONS, EVP_sha256(), 
                             AES_KEY_LEN, out_key);
}


// --- OPERAZIONI DI CIFRATURA (AES-256-CBC) ---

int crypto_encrypt(const unsigned char *plaintext, int plaintext_len, 
                   const unsigned char *key, unsigned char *out_buffer) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[IV_LEN];
    
    // Generiamo un IV casuale per ogni cifratura
    RAND_bytes(iv, IV_LEN);
    
    // Scriviamo l'IV all'inizio del buffer di output
    memcpy(out_buffer, iv, IV_LEN);

    int len, ciphertext_len;
    
    // Inizializzazione AES-256-CBC
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    
    // Cifratura dei dati (scriviamo dopo i 16 byte dell'IV)
    EVP_EncryptUpdate(ctx, out_buffer + IV_LEN, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    // Finalizzazione (gestione del padding)
    EVP_EncryptFinal_ex(ctx, out_buffer + IV_LEN + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    
    // Restituiamo la lunghezza totale del blob: IV + Dati Cifrati
    return ciphertext_len + IV_LEN;
}

int crypto_decrypt(const unsigned char *ciphertext_blob, int blob_len, 
                   const unsigned char *key, unsigned char *out_plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[IV_LEN];
    
    // Recuperiamo l'IV dai primi 16 byte del blob
    memcpy(iv, ciphertext_blob, IV_LEN);

    int len, plaintext_len;

    // Inizializzazione per la decifratura
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    
    // Decifratura (partiamo dal byte 16 del blob)
    EVP_DecryptUpdate(ctx, out_plaintext, &len, 
                      ciphertext_blob + IV_LEN, blob_len - IV_LEN);
    plaintext_len = len;

    // Finalizzazione: se restituisce <= 0, la chiave è errata!
    if (EVP_DecryptFinal_ex(ctx, out_plaintext + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; 
    }
    plaintext_len += len;
    
    // Aggiungiamo il terminatore di stringa per sicurezza
    out_plaintext[plaintext_len] = '\0';

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}
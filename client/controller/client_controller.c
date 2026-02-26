#include "client_controller.h"

// Il controller conosce i layer inferiori e li coordina
#include "../service/client_service.h"
#include "../service/client_enrollment.h"
#include "../service/client_utils.h"

#include <string.h>

// =========================================================
// --- 1. CONFIGURAZIONE E UTENTE ---
// =========================================================

void controller_set_server_config(const char *ip) {
    client_service_set_server_config(ip);
}

void controller_set_default_username(){
    client_service_set_default_username();
}


const char* controller_get_username() {
    return client_service_get_username();
}

const char* controller_get_system_user() {
    return get_system_user();
}

// =========================================================
// --- 2. SETUP CA (OUT OF BAND) ---
// =========================================================

int controller_check_client_has_ca() {
    return client_service_has_ca();
}

int controller_import_ca(const char *source_path) {
    return client_service_import_ca(source_path);
}

// =========================================================
// --- 3. ENROLLMENT (REGISTRAZIONE DISPOSITIVO) ---
// =========================================================

int controller_needs_enrollment() {
    return client_service_needs_enrollment();
}

int controller_request_enrollment(const char *user) {
    // Richiesta preliminare al server per verificare se accetta enrollment
    return client_service_request_enrollment(user);
}

int controller_perform_enrollment(const char *user, const char *otp) {
    /* * ORCHESTRAZIONE PURA:
     * Il Controller detta il flusso di business, il Service esegue.
     */
     
    // Passo 1: Ordina la generazione del CSR
    if (client_enrollment_generate_csr(user) != 0) {
        return -1;
    }
    
    // Passo 2: Ordina l'invio al server, il parsing della risposta e il salvataggio del .crt
    int res = client_enrollment_send_and_save_cert(user, otp);
    
    // Passo 3: Indipendentemente dall'esito, fa pulire i file temporanei
    client_enrollment_cleanup_csr(user);
    
    // Ritorna l'esito alla GUI
    return res;
}

// =========================================================
// --- 4. GESTIONE CHIAVI E SBLOCCO SESSIONE ---
// =========================================================

int controller_set_crypto_password() {
    // Il controller non riceve più la password, ma imposta solo l'intenzione.
    return client_service_set_crypto_password();
}

int controller_set_crypto_usb_path(const char *path) {
    // Delega al service il salvataggio del percorso del file.
    // Il service verificherà che il file sia leggibile prima di accettarlo.
    return client_service_set_crypto_usb_path(path);
}

int controller_generate_new_usb_key(const char *path) {
    return client_service_generate_new_usb_key(path);
}
int controller_is_using_password() {
    return client_service_is_using_password();
}

// =========================================================
// --- 5. SESSIONE E VAULT (MTLS) ---
// =========================================================

int controller_init_session() {
    // Il controller si assicura che non ci siano vecchie sessioni appese
    client_service_close_session();
    
    // Tenta di inizializzare la nuova connessione sicura
    return client_service_init_session(); 
}
int controller_store_data_encrypted(const char *svc, const char *pass, const char *live_pw, char *out_server_resp, size_t resp_len) {
    // Il controller delega interamente l'operazione. Il service si occuperà 
    // di cifrare, convertire in HEX e impacchettare per il protocollo di rete.
    return client_service_store_data(svc, pass, live_pw, out_server_resp, resp_len);

}

int controller_fetch_vault(const char *live_pw, void (*data_handler)(const char *svc, const char *pass)) {
    // Il controller non tocca più le stringhe grezze.
    // Passa la callback della GUI direttamente al service.
    // Il service scaricherà, parserà, decifrerà e chiamerà la callback per ogni riga valida.
   return client_service_fetch_and_parse_vault(live_pw, data_handler);
}


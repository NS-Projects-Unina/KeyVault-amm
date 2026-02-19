#ifndef PKI_H
#define PKI_H

// Crea la cartella "certs" se non esiste
void init_pki_directory();

// Funzione lato SERVER: Crea la Root CA e il certificato del server se non esistono
void setup_server_infrastructure();

// Funzione CONDIVISA: Genera chiave, CSR e certificato per un nuovo utente (Client)
// Ritorna 0 in caso di successo, -1 in caso di errore
int generate_client_certificate(const char *username);

#endif // PKI_H
#ifndef PKI_H
#define PKI_H

//Si assicura che la cartella certs/ esista nel filesystem, altrimenti la crea
//con i permessi 0700 (solo il proprietario può leggere/scrivere/eseguire)
void init_pki_directory(); 

void setup_server_infrastructure();

//Genera una chiave privata e una CSR (firmata con la chiave privata precedentemente chiesta) per l'utente specificato, salvandole in certs/username.key e certs/username.csr
int pki_generate_csr(const char *username);

//Firma la CSR generata dal client usando la CA del server.
int pki_sign_client_request(const char *username);

#endif
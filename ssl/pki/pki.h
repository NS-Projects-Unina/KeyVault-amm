#ifndef PKI_H
#define PKI_H

#define SERVER_CERTS_PATH "server_storage/certs/"
#define SERVER_BASE_DIR   "server_storage"

//Si assicura che la cartella certs/ esista nel filesystem, altrimenti la crea
//con i permessi 0700 (solo il proprietario può leggere/scrivere/eseguire)
void init_pki_directory(); 

void setup_server_infrastructure();

//Firma la CSR generata dal client usando la CA del server.
int pki_sign_client_request(const char *username);

#endif
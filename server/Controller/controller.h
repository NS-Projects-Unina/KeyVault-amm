#ifndef SERVER_CONTROLLER_H
#define SERVER_CONTROLLER_H

/**
 * Punto di ingresso principale del Server.
 * Inizializza i servizi, si mette in ascolto e gestisce il ciclo di vita delle sessioni.
 * @return 0 in caso di chiusura volontaria, -1 in caso di errore.
 */
int run_server_controller();

#endif
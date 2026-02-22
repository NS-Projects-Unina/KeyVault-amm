#include <gtk/gtk.h>
#include "gui_manager/gui_manager.h"


//Appena riceve il segnale, delega tutto a setup_main_window, che si occupa di costruire l'interfaccia grafica e collegare le callback
static void on_activate(GtkApplication *app, gpointer user_data) {
    (void)user_data; // Questo toglie il warning "unused parameter"
    setup_main_window(app); 
}

int main(int argc, char **argv) {
    //Crea l'oggetto GtkApplication, registra l'applicazione presso il sistema Operativo con ID (org.keyvault.client)
    GtkApplication *app = gtk_application_new("org.keyvault.client", G_APPLICATION_DEFAULT_FLAGS);
    // Il SO controlla se è già in esecuzione un'istanza con lo stesso ID, e in quel caso invia un messaggio all'istanza esistente invece di avviarne una nuova
    //Tecnicamente la registrazione apre un canale IPC (Inter-Process Communication): Sono org.keyvault.client. Se qualcuno bussa alla mia porta o se il sistema ha aggiornamenti grafici per me, fammelo sapere qui   

    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);
    //Ponte tra il main e il gui_manager (logica), delegando il lavoro a setup_main_window.
    int status = g_application_run(G_APPLICATION(app), argc, argv); // Avvia l'applicazione
    
    g_object_unref(app); // Libera le risorse allocate per l'applicazione
    return status;
}
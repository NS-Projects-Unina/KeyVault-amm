#include <gtk/gtk.h>
#include "gui_manager/gui_manager.h"

//Appena riceve il segnale, delega tutto a setup_main_window, che si occupa di costruire l'interfaccia grafica
static void on_activate(GtkApplication *app, gpointer user_data) {
    (void)user_data; // Questo toglie il warning "unused parameter"
    client_service_set_default_username(); // Imposta l'username di default nel Context, passando per il service
    setup_main_window(app); 
}

int main(int argc, char **argv) {

    // 1. Creazione dell'oggetto GtkApplication.
    // 2. Il programma si identifica con [org.keyvault.client] al SO.
    // 3. Il SO verifica se esiste un processo con lo stesso ID  (SINGLETON):
    //    - Se esiste, il controllo viene passato a quel processo (e questo termina)
    //    - Se non esiste, viene creato un nuovo processo (il nostro)
    GtkApplication *app = gtk_application_new("org.keyvault.client", G_APPLICATION_DEFAULT_FLAGS);
    

    // Quando c'è l'evento "activate" allora l'app è pronta, ed esegue la callback on_activate
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);


    //Avvia il Main Loop, dunque il programma si blocca qui e attende gli input dell'utente.
    int status = g_application_run(G_APPLICATION(app), argc, argv); // Avvia l'applicazione
    //Rimarremo in questo punto fino a che non verrà chiusa la finestra

    g_object_unref(app); // Libera le risorse allocate per l'applicazione
    return status;
}
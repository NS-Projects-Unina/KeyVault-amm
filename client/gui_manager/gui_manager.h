#ifndef GUI_PAGES_H
#define GUI_PAGES_H

#include <gtk/gtk.h>


void setup_main_window(GtkApplication *app);

// Funzioni di creazione pagine
GtkWidget* create_intro_page(void);
GtkWidget* create_enrollment_page(void);
GtkWidget* create_key_select_page(void);
GtkWidget* create_connect_page(void);
GtkWidget* create_vault_page(void);

// Getter per i widget dinamici (serviranno ai gestori per leggere i dati)
GtkWidget* gui_get_otp_entry(void);
GtkWidget* gui_get_password_entry(void);
GtkWidget* gui_get_vault_list(void);

#endif
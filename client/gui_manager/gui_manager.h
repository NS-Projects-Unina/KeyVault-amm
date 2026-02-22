#ifndef GUI_MANAGER_H
#define GUI_MANAGER_H

#include <gtk/gtk.h>

// Dichiariamo le funzioni che vogliamo usare in client_main.c
void setup_main_window(GtkApplication *app);
GtkWidget* create_enrollment_page();

#endif
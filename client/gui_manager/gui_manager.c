#include "gui_manager.h"
#include "service/client_enrollment.h"
#include "service/client_utils.h"
#include "service/client_service.h"
#include "service/crypto_utils.h"
#include <gtk/gtk.h>

// --- Widget Globali ---
static GtkWidget *stack;
static GtkWidget *vault_list;
static GtkWidget *otp_entry;
static GtkWidget *password_entry;
static GtkWidget *status_enroll;
static GtkWidget *status_key;
static GtkWidget *status_connect;

// --- PROTOTIPI DELLE FUNZIONI DI PAGINA (Per evitare warning di dichiarazione) ---
GtkWidget* create_intro_page();
GtkWidget* create_enrollment_page();
GtkWidget* create_key_select_page();
GtkWidget* create_connect_page();
GtkWidget* create_vault_page();

// --- 1. LOGICA DASHBOARD (VAULT) ---

void add_vault_row_callback(const char *service, const char *password) {
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 15);
    GtkWidget *lbl_svc = gtk_label_new(service);
    GtkWidget *lbl_pass = gtk_label_new(password);

    gtk_widget_set_size_request(lbl_svc, 180, -1);
    gtk_label_set_xalign(GTK_LABEL(lbl_svc), 0);
    
    gtk_box_append(GTK_BOX(row), lbl_svc);
    gtk_box_append(GTK_BOX(row), lbl_pass);
    gtk_list_box_append(GTK_LIST_BOX(vault_list), row);
}

static void on_refresh_clicked(GtkWidget *widget, gpointer data) {
    (void)widget; (void)data;
    GtkWidget *child;
    while ((child = gtk_widget_get_first_child(vault_list)) != NULL) 
        gtk_list_box_remove(GTK_LIST_BOX(vault_list), child);
    
    client_service_fetch_vault(add_vault_row_callback);
}

static void on_actual_save(GtkButton *btn, gpointer data) {
    GtkWidget *dialog = GTK_WIDGET(data);
    GtkWidget *ent_svc = GTK_WIDGET(g_object_get_data(G_OBJECT(btn), "svc"));
    GtkWidget *ent_pass = GTK_WIDGET(g_object_get_data(G_OBJECT(btn), "pass"));

    const char *svc = gtk_editable_get_text(GTK_EDITABLE(ent_svc));
    const char *pass = gtk_editable_get_text(GTK_EDITABLE(ent_pass));

    if (strlen(svc) > 0 && strlen(pass) > 0) {
        char resp[1024];
        client_service_store_data_encrypted(svc, pass, resp, sizeof(resp));
        gtk_window_destroy(GTK_WINDOW(dialog));
        on_refresh_clicked(NULL, NULL);
    }
}

static void on_add_password_clicked(GtkWidget *widget, gpointer data) {
    (void)data;
    GtkWidget *dialog = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(dialog), "Nuova Credenziale");
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_transient_for(GTK_WINDOW(dialog), GTK_WINDOW(gtk_widget_get_root(widget)));

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    // CORREZIONE MARGINI GTK 4
    gtk_widget_set_margin_top(vbox, 15);
    gtk_widget_set_margin_bottom(vbox, 15);
    gtk_widget_set_margin_start(vbox, 15);
    gtk_widget_set_margin_end(vbox, 15);
    
    gtk_window_set_child(GTK_WINDOW(dialog), vbox);

    GtkWidget *ent_svc = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(ent_svc), "Nome Servizio");
    gtk_box_append(GTK_BOX(vbox), ent_svc);

    GtkWidget *ent_pass = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(ent_pass), FALSE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(ent_pass), "Password");
    gtk_box_append(GTK_BOX(vbox), ent_pass);

    GtkWidget *btn_save = gtk_button_new_with_label("Cifra e Salva");
    g_object_set_data(G_OBJECT(btn_save), "svc", ent_svc);
    g_object_set_data(G_OBJECT(btn_save), "pass", ent_pass);
    g_signal_connect(btn_save, "clicked", G_CALLBACK(on_actual_save), dialog);
    
    gtk_box_append(GTK_BOX(vbox), btn_save);
    gtk_window_present(GTK_WINDOW(dialog));
}

// --- 2. LOGICA CONNESSIONE (STEP 3) ---

static void on_connect_clicked(GtkWidget *widget, gpointer data) {
    (void)widget; (void)data;
    gtk_label_set_text(GTK_LABEL(status_connect), "Stabilendo tunnel mTLS sicuro...");

    if (client_service_init_session() == 0) {
        gtk_stack_set_visible_child_name(GTK_STACK(stack), "vault_page");
        on_refresh_clicked(NULL, NULL);
    } else {
        gtk_label_set_text(GTK_LABEL(status_connect), "❌ Connessione fallita. Controlla il server.");
    }
}

// --- 3. LOGICA SCELTA CHIAVE (STEP 2) ---

static void on_key_ready() {
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "connect_page");
}

static void on_password_unlock_clicked(GtkWidget *widget, gpointer data) {
    (void)widget; (void)data;
    const char *password = gtk_editable_get_text(GTK_EDITABLE(password_entry));
    unsigned char derived_key[32]; 
    if (crypto_derive_from_password(password, derived_key) == 0) {
        client_service_set_session_key(derived_key);
        on_key_ready();
    } else {
        gtk_label_set_text(GTK_LABEL(status_key), "[-] Errore nella derivazione.");
    }
}

static void on_usb_file_opened(GObject *source, GAsyncResult *res, gpointer data) {
    (void)data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG(source);
    GFile *file = gtk_file_dialog_open_finish(dialog, res, NULL);
    if (file) {
        char *path = g_file_get_path(file);
        unsigned char loaded_key[32];
        if (crypto_load_usb_key(path, loaded_key) == 0) {
            client_service_set_session_key(loaded_key);
            on_key_ready();
        } else {
            gtk_label_set_text(GTK_LABEL(status_key), "[-] File chiave non valido.");
        }
        g_free(path); g_object_unref(file);
    }
}

static void on_usb_load_clicked(GtkWidget *widget, gpointer data) {
    (void)data;
    GtkFileDialog *dialog = gtk_file_dialog_new();
    gtk_file_dialog_open(dialog, GTK_WINDOW(gtk_widget_get_root(widget)), NULL, on_usb_file_opened, NULL);
}

// --- 4. LOGICA ENROLLMENT (STEP 1) ---

static void on_enroll_submit(GtkWidget *widget, gpointer data) {
    (void)widget; (void)data;
    const char *otp = gtk_editable_get_text(GTK_EDITABLE(otp_entry));
    if (client_service_perform_enrollment(get_system_user(), otp) == 0) {
        gtk_stack_set_visible_child_name(GTK_STACK(stack), "key_page");
    } else {
        gtk_label_set_text(GTK_LABEL(status_enroll), "❌ OTP errato.");
    }
}

static void on_start_clicked(GtkWidget *widget, gpointer data) {
    (void)widget; (void)data;
    if (client_service_needs_enrollment()) {
        client_service_request_enrollment(get_system_user());
        gtk_stack_set_visible_child_name(GTK_STACK(stack), "enroll_page");
    } else {
        gtk_stack_set_visible_child_name(GTK_STACK(stack), "key_page");
    }
}

// --- COSTRUZIONE UI ---

GtkWidget* create_intro_page() {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 25);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER); gtk_widget_set_valign(box, GTK_ALIGN_CENTER);
    GtkWidget *lbl = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(lbl), "<span size='24000' weight='bold'>KeyVault</span>\nSicurezza Zero-Knowledge");
    gtk_label_set_justify(GTK_LABEL(lbl), GTK_JUSTIFY_CENTER);
    gtk_box_append(GTK_BOX(box), lbl);
    GtkWidget *btn = gtk_button_new_with_label("Inizia Procedura");
    gtk_widget_set_size_request(btn, 220, 60);
    g_signal_connect(btn, "clicked", G_CALLBACK(on_start_clicked), NULL);
    gtk_box_append(GTK_BOX(box), btn);
    return box;
}

GtkWidget* create_enrollment_page() {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER); gtk_widget_set_valign(box, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(box), gtk_label_new("Passo 1: Registrazione Dispositivo"));
    otp_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(otp_entry), "Codice OTP");
    gtk_box_append(GTK_BOX(box), otp_entry);
    GtkWidget *btn = gtk_button_new_with_label("Conferma Registrazione");
    g_signal_connect(btn, "clicked", G_CALLBACK(on_enroll_submit), NULL);
    gtk_box_append(GTK_BOX(box), btn);
    status_enroll = gtk_label_new("");
    gtk_box_append(GTK_BOX(box), status_enroll);
    return box;
}

GtkWidget* create_key_select_page() {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER); gtk_widget_set_valign(box, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(box), gtk_label_new("Passo 2: Sblocco Criptazione"));
    password_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(password_entry), FALSE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(password_entry), "Master Password");
    gtk_box_append(GTK_BOX(box), password_entry);
    GtkWidget *btn_pw = gtk_button_new_with_label("Sblocca con Password");
    g_signal_connect(btn_pw, "clicked", G_CALLBACK(on_password_unlock_clicked), NULL);
    gtk_box_append(GTK_BOX(box), btn_pw);
    GtkWidget *btn_usb = gtk_button_new_with_label("Sblocca con USB");
    g_signal_connect(btn_usb, "clicked", G_CALLBACK(on_usb_load_clicked), NULL);
    gtk_box_append(GTK_BOX(box), btn_usb);
    status_key = gtk_label_new("Carica la tua chiave privata locale");
    gtk_box_append(GTK_BOX(box), status_key);
    return box;
}

GtkWidget* create_connect_page() {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER); gtk_widget_set_valign(box, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(box), gtk_label_new("Passo 3: Connessione al Server"));
    GtkWidget *btn = gtk_button_new_with_label("Stabilisci Tunnel mTLS");
    gtk_widget_add_css_class(btn, "suggested-action");
    gtk_widget_set_size_request(btn, 200, 50);
    g_signal_connect(btn, "clicked", G_CALLBACK(on_connect_clicked), NULL);
    gtk_box_append(GTK_BOX(box), btn);
    status_connect = gtk_label_new("Pronto alla connessione sicura");
    gtk_box_append(GTK_BOX(box), status_connect);
    return box;
}

GtkWidget* create_vault_page() {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_widget_set_margin_top(box, 20); gtk_widget_set_margin_bottom(box, 20);
    gtk_widget_set_margin_start(box, 20); gtk_widget_set_margin_end(box, 20);
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span size='large' weight='bold'>I Tuoi Dati Protetti</span>");
    gtk_box_append(GTK_BOX(box), title);
    GtkWidget *sw = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(sw, TRUE);
    vault_list = gtk_list_box_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(sw), vault_list);
    gtk_box_append(GTK_BOX(box), sw);
    GtkWidget *action_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign(action_bar, GTK_ALIGN_CENTER);
    GtkWidget *btn_add = gtk_button_new_with_label("Aggiungi Password");
    GtkWidget *btn_refresh = gtk_button_new_with_label("Sincronizza");
    g_signal_connect(btn_refresh, "clicked", G_CALLBACK(on_refresh_clicked), NULL);
    g_signal_connect(btn_add, "clicked", G_CALLBACK(on_add_password_clicked), NULL);
    gtk_box_append(GTK_BOX(action_bar), btn_add);
    gtk_box_append(GTK_BOX(action_bar), btn_refresh);
    gtk_box_append(GTK_BOX(box), action_bar);
    return box;
}

void setup_main_window(GtkApplication *app) {
    GtkWidget *window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "KeyVault Client");
    gtk_window_set_default_size(GTK_WINDOW(window), 500, 450);

    stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(stack), GTK_STACK_TRANSITION_TYPE_SLIDE_LEFT_RIGHT);
    gtk_window_set_child(GTK_WINDOW(window), stack);

    gtk_stack_add_named(GTK_STACK(stack), create_intro_page(), "intro_page");
    gtk_stack_add_named(GTK_STACK(stack), create_enrollment_page(), "enroll_page");
    gtk_stack_add_named(GTK_STACK(stack), create_key_select_page(), "key_page");
    gtk_stack_add_named(GTK_STACK(stack), create_connect_page(), "connect_page");
    gtk_stack_add_named(GTK_STACK(stack), create_vault_page(), "vault_page");

    gtk_stack_set_visible_child_name(GTK_STACK(stack), "intro_page");
    gtk_window_present(GTK_WINDOW(window));
}
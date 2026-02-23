#include "gui_manager.h"
#include "service/client_enrollment.h"
#include "service/client_utils.h"
#include "service/client_service.h"
#include <gtk/gtk.h>

// --- Widget Globali ---
//Sono riferimenti a pezzi dell'interfaccia che aggiorneremo dopo
static GtkWidget *stack;
static GtkWidget *vault_list;
static GtkWidget *otp_entry;
static GtkWidget *password_entry;
static GtkWidget *status_enroll;
static GtkWidget *status_key;
static GtkWidget *status_connect;
static GtkWidget *status_intro;
static GtkWidget *ip_entry;
static GtkWidget *server_toggle;
static GtkWidget *user_info_label;
static GtkWidget *status_ca;

// --- PROTOTIPI DELLE FUNZIONI DI PAGINA (Per evitare warning di dichiarazione) ---
GtkWidget* create_intro_page();
GtkWidget* create_enrollment_page();
GtkWidget* create_key_select_page();
GtkWidget* create_connect_page();
GtkWidget* create_vault_page();


// --- 4. LOGICA DASHBOARD (VAULT) ---

// Callback che aggiunge una riga alla lista del vault, usata come argomento nella funzione di fetch
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

// ---4. Callback per il bottone di refresh, svuota la lista e chiama la funzione di fetch passando la callback che aggiunge le righe alla lista
static void on_refresh_clicked(GtkWidget *widget, gpointer data) {
    (void)widget; (void)data;
    GtkWidget *child;
    while ((child = gtk_widget_get_first_child(vault_list)) != NULL) 
        gtk_list_box_remove(GTK_LIST_BOX(vault_list), child);
    
    // Chiama la funzione di fetch passando la callback che aggiunge le righe alla lista
    client_service_fetch_vault(add_vault_row_callback);
}

// --- 4. Callback per il bottone di salvataggio della nuova password, prende i dati dai campi di testo, chiama la funzione di store e aggiorna la lista
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

// --- 4. Callback per il bottone di aggiunta di una nuova password, apre un dialog con i campi per inserire servizio e password, e un bottone di conferma che chiama la callback di salvataggio
static void on_add_password_clicked(GtkWidget *widget, gpointer data) {
    (void)data;
    GtkWidget *dialog = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(dialog), "Nuova Credenziale");
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_transient_for(GTK_WINDOW(dialog), GTK_WINDOW(gtk_widget_get_root(widget)));

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
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

// --- 3. LOGICA CONNESSIONE ---
static void on_connect_clicked(GtkWidget *widget, gpointer data) {
    (void)widget; (void)data;
    gtk_label_set_text(GTK_LABEL(status_connect), "Stabilendo tunnel mTLS sicuro...");

    // Prova a stabilire la connessione mtls con il server, se va tutto bene, mostra la pagina del vault, altrimenti mostra un messaggio di errore
    if (client_service_init_session() == 0) {
        gtk_stack_set_visible_child_name(GTK_STACK(stack), "vault_page");
        on_refresh_clicked(NULL, NULL);
    } else {
        gtk_label_set_text(GTK_LABEL(status_connect), "❌ Connessione fallita. Controlla il server.");
    }
}

// --- 2. LOGICA SCELTA CHIAVE ---
static void on_key_ready() {
    // Se la chiave è pronta, passa direttamente alla fase di connessione
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "connect_page");
}

// Callback per il bottone della scelta della Key con password. 
// Deriva la chiave e, se tutto va bene, passa alla fase di connessione
static void on_password_unlock_clicked(GtkWidget *widget, gpointer data) {
    (void)widget; (void)data;
    const char *password = gtk_editable_get_text(GTK_EDITABLE(password_entry)); 
    
    // Deleghiamo la derivazione e l'impostazione della chiave al Service
    if (client_service_unlock_with_password(password) == 0) {
        on_key_ready(); // Passa alla fase di connessione
    } else {
        gtk_label_set_text(GTK_LABEL(status_key), "[-] Errore nella derivazione della chiave.");
    }
}

// --- 2. Callback per  l'utente sceglie un file di chiave USB. ---
static void on_usb_file_opened(GObject *source, GAsyncResult *res, gpointer data) {
    (void)data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG(source);
    GFile *file = gtk_file_dialog_open_finish(dialog, res, NULL);

    if (file) {
        char *path = g_file_get_path(file);
        
        // Deleghiamo il caricamento e la convalida al Service
        if (client_service_unlock_with_usb(path) == 0) {
            on_key_ready();
        } else {
            gtk_label_set_text(GTK_LABEL(status_key), "[-] File chiave non valido o corrotto.");
        }
        g_free(path); 
        g_object_unref(file);
    }
}

// --- 2. Callback per il bottone di caricamento della chiave da USB. ---
static void on_usb_load_clicked(GtkWidget *widget, gpointer data) {
    (void)data;
    // Apre un file dialog per scegliere il file della chiave USB. 
    //Quando l'utente sceglie un file, viene chiamata la callback on_usb_file_opened
    GtkFileDialog *dialog = gtk_file_dialog_new(); 
    gtk_file_dialog_open(dialog, GTK_WINDOW(gtk_widget_get_root(widget)), NULL, on_usb_file_opened, NULL);
}

// --- 2. Callback per il salvataggio della nuova chiave generata
static void on_usb_generate_save_response(GObject *source, GAsyncResult *res, gpointer data) {
    (void)data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG(source);
    GFile *file = gtk_file_dialog_save_finish(dialog, res, NULL);

    if (file) {
        char *path = g_file_get_path(file);
        
        // 1. Generazione fisica (rimane crypto_utils finché non sposti anche questa)
        if (client_service_generate_new_usb_key(path) == 0) {
            g_print("[+] Nuova chiave generata e caricata: %s\n", path);
            on_key_ready(); 
        } else {
            g_warning("[-] Impossibile generare la chiave");
        }
        g_free(path);
        g_object_unref(file);
    }
}

// --- 2.Handler per il click sul bottone "Genera"
void on_usb_generate_clicked(GtkWidget *widget, gpointer data) {
    (void)data;
    GtkFileDialog *dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Scegli dove salvare la nuova chiave");
    gtk_file_dialog_set_initial_name(dialog, "vault.key");

    // Apre il dialog in modalità "salva"
    gtk_file_dialog_save(dialog, GTK_WINDOW(gtk_widget_get_root(widget)), 
                         NULL, on_usb_generate_save_response, NULL);
}



// --- 1. LOGICA ENROLLMENT (STEP 1) ---
GtkWidget* gui_get_status_intro() { return status_intro; }

static void on_enroll_submit(GtkWidget *widget, gpointer data) {
    (void)widget; (void)data;
     //Prende il testo inserito dall'utente nel campo OTP
    const char *otp = gtk_editable_get_text(GTK_EDITABLE(otp_entry));
    
    if (client_service_perform_enrollment(get_system_user(), otp) == 0) { // Se l'enrollment ha successo, passa alla pagina di scelta chiave
        gtk_stack_set_visible_child_name(GTK_STACK(stack), "key_page");
    } else {
        gtk_label_set_text(GTK_LABEL(status_enroll), "❌ OTP errato.");
    }
}

// --- 0. LOGICA INIZIALE  ---

// --- LOGICA IMPORTAZIONE CA (Passo 0) ---

// Callback per la selezione del file CA tramite FileDialog

static void on_ca_file_selected(GObject *source, GAsyncResult *res, gpointer data) {
    (void)data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG(source);
    GFile *file = gtk_file_dialog_open_finish(dialog, res, NULL);

    if (file) {
        char *path = g_file_get_path(file);
        
        // La GUI passa solo l'ordine al Service
        if (client_service_import_ca(path) == 0) {
            gtk_label_set_text(GTK_LABEL(status_ca), "Certificato CA importato!");
            gtk_stack_set_visible_child_name(GTK_STACK(stack), "intro_page");
        } else {
            gtk_label_set_text(GTK_LABEL(status_ca), "Errore durante l'importazione.");
        }

        g_free(path); 
        g_object_unref(file);
    }
}

static void on_import_ca_clicked(GtkWidget *widget, gpointer data) {
    (void)data;
    GtkFileDialog *dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Seleziona il certificato ca.crt ricevuto dall'Admin");
    gtk_file_dialog_open(dialog, GTK_WINDOW(gtk_widget_get_root(widget)), NULL, on_ca_file_selected, NULL);
}


// In gui_handlers.c
void on_start_clicked(GtkWidget *widget, gpointer data) {
    (void)widget; (void)data;
    GtkWidget *status_lbl = gui_get_status_intro();

    if (client_service_needs_enrollment()) {
        // Chiamata al service: tenta di contattare il server via TLS basico
        if (client_service_request_enrollment(get_system_user()) == 0) {
            // Successo: il server ha risposto "OK"
            gtk_label_set_text(GTK_LABEL(status_lbl), ""); // Pulisce eventuali errori precedenti
            gtk_stack_set_visible_child_name(GTK_STACK(stack), "enroll_page"); 
        } else {
            // Fallimento: connessione fallita o risposta negativa
            gtk_label_set_text(GTK_LABEL(status_lbl), "⚠️ Il server non accetta connessioni. Verifica che sia attivo.");
        }
    } else {
        // Enrollment non necessario (certificati già presenti)
        gtk_stack_set_visible_child_name(GTK_STACK(stack), "key_page"); 
    }
}

// Gestione dell'abilitazione del campo IP in base allo switch
static void on_server_toggle_changed(GtkSwitch *sw, gpointer data) {
    (void)data;
    gtk_widget_set_sensitive(ip_entry, gtk_switch_get_active(sw));
}


static void on_config_done(GtkWidget *widget, gpointer data) {
    (void)widget; (void)data;
    
    // 1. Comando al service per impostare l'IP
    const char *final_ip = gtk_switch_get_active(GTK_SWITCH(server_toggle)) ? 
                           gtk_editable_get_text(GTK_EDITABLE(ip_entry)) : "127.0.0.1";
    client_service_set_server_config(final_ip);

    // 2. Interrogazione del Service per la CA
    if (client_service_has_ca()) {
        // Se la CA c'è, proseguiamo alla intro
        gtk_stack_set_visible_child_name(GTK_STACK(stack), "intro_page");
    } else {
        // Se manca, forziamo l'utente a passare per la pagina di importazione
        gtk_stack_set_visible_child_name(GTK_STACK(stack), "ca_page"); 
    }
}
// --- COSTRUZIONE UI ---

// Creazione della nuova pagina di configurazione
GtkWidget* create_config_page() {

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);

    gtk_box_append(GTK_BOX(box), gtk_label_new("Configurazione Server di Rete"));

    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_append(GTK_BOX(row), gtk_label_new("Usa IP personalizzato (non localhost)"));
    server_toggle = gtk_switch_new();
    g_signal_connect(server_toggle, "state-set", G_CALLBACK(on_server_toggle_changed), NULL);
    gtk_box_append(GTK_BOX(row), server_toggle);
    gtk_box_append(GTK_BOX(box), row);

    ip_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(ip_entry), "Es: 192.168.1.50");
    gtk_widget_set_sensitive(ip_entry, FALSE); // Disabilitato di default (localhost)
    gtk_box_append(GTK_BOX(box), ip_entry);

    GtkWidget *btn = gtk_button_new_with_label("Conferma e Prosegui");
    gtk_widget_add_css_class(btn, "suggested-action");
    g_signal_connect(btn, "clicked", G_CALLBACK(on_config_done), NULL);
    gtk_box_append(GTK_BOX(box), btn);

    return box;
}

GtkWidget* create_intro_page() {
    // 1. Box verticale con spacing 0 (gestiamo lo spazio noi con i margini)
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);

    // 2. Caricamento Logo
    GError *error = NULL;
    // Portiamo la scala a 380px per farlo davvero grande
    GdkPixbuf *pixbuf = gdk_pixbuf_new_from_file_at_scale(
        "client/gui_manager/assets/logo_full.png", 
        380, 380, 
        TRUE, 
        &error
    );

    GtkWidget *logo_widget;
    if (error) {
        g_warning("Errore logo: %s", error->message);
        g_error_free(error);
        logo_widget = gtk_image_new_from_icon_name("security-high-symbolic");
        gtk_image_set_pixel_size(GTK_IMAGE(logo_widget), 200);
    } else {
        logo_widget = gtk_image_new_from_pixbuf(pixbuf);
        g_object_unref(pixbuf); // Liberiamo la memoria subito dopo l'uso
    }

    // Forziamo le dimensioni del widget per "spingere" i bordi della box
    gtk_widget_set_size_request(logo_widget, 380, 380);
    gtk_image_set_pixel_size(GTK_IMAGE(logo_widget), 380);
    
    gtk_box_append(GTK_BOX(box), logo_widget);

    // 3. Bottone (Centrato e vicino)
    GtkWidget *btn = gtk_button_new_with_label("Inizia Procedura");
    gtk_widget_set_size_request(btn, 240, 70);
    gtk_widget_set_halign(btn, GTK_ALIGN_CENTER); // Evita che il bottone si allarghi troppo
    
    // SPAZIO: Regola questo numero per avvicinare/allontanare (es. 10 è molto vicino)
    gtk_widget_set_margin_top(btn, 10); 
    
    gtk_widget_add_css_class(btn, "suggested-action");
    g_signal_connect(btn, "clicked", G_CALLBACK(on_start_clicked), NULL);
    gtk_box_append(GTK_BOX(box), btn);

    status_intro = gtk_label_new("");
    gtk_widget_add_css_class(status_intro, "error-text"); // Classe CSS per il colore rosso
    gtk_widget_set_margin_top(status_intro, 10);
    gtk_box_append(GTK_BOX(box), status_intro);

    return box;
}

// Creazione della pagina di Enrollment
// Avrà un campo di testo ("Inserire OTP") e un bottone di conferma.
GtkWidget* create_enrollment_page() {
    // Creazione di un box verticale per organizzare gli elementi della pagina
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER); gtk_widget_set_valign(box, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(box), gtk_label_new("Passo 1: Registrazione Dispositivo"));
    
    // Creazione del campo di testo per l'OTP, con un placeholder che scompare quando l'utente inizia a scrivere
    otp_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(otp_entry), "Codice OTP");
    gtk_box_append(GTK_BOX(box), otp_entry);

    // Creazione del bottone di conferma, che quando cliccato esegue la callback on_enroll_submit
    GtkWidget *btn = gtk_button_new_with_label("Conferma Registrazione");
    g_signal_connect(btn, "clicked", G_CALLBACK(on_enroll_submit), NULL);
    gtk_box_append(GTK_BOX(box), btn);

    // Aggiunta di una label per mostrare eventuali messaggi di errore o stato
    status_enroll = gtk_label_new("");
    gtk_box_append(GTK_BOX(box), status_enroll);

    return box;
}

// Creazione della pagina di scelta chiave, con opzioni per sbloccare con password o con chiave USB, e un messaggio di stato
// con possibilità anche di generare una nuova chiave USB (per chi non ha già una chiave pronta) 
GtkWidget* create_key_select_page() {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER); 
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);
    
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span size='large' weight='bold'>Passo 2: Configurazione Chiave</span>");
    gtk_box_append(GTK_BOX(box), title);

    // --- SEZIONE SBLOCCO (Password) ---
    password_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(password_entry), FALSE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(password_entry), "Master Password");
    gtk_box_append(GTK_BOX(box), password_entry);
    
    GtkWidget *btn_pw = gtk_button_new_with_label("Sblocca con Password");
    g_signal_connect(btn_pw, "clicked", G_CALLBACK(on_password_unlock_clicked), NULL);
    gtk_box_append(GTK_BOX(box), btn_pw);

    // --- SEZIONE USB (Caricamento e Generazione) ---
    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_append(GTK_BOX(box), sep);

    GtkWidget *btn_usb_load = gtk_button_new_with_label("Sblocca con USB esistente");
    g_signal_connect(btn_usb_load, "clicked", G_CALLBACK(on_usb_load_clicked), NULL);
    gtk_box_append(GTK_BOX(box), btn_usb_load);

    // NUOVO: Bottone per generare una nuova chiave
    GtkWidget *btn_usb_gen = gtk_button_new_with_label("Genera Nuova Chiave su USB");
    gtk_widget_add_css_class(btn_usb_gen, "outline"); // Uno stile diverso per distinguerlo
    g_signal_connect(btn_usb_gen, "clicked", G_CALLBACK(on_usb_generate_clicked), NULL);
    gtk_box_append(GTK_BOX(box), btn_usb_gen);

    status_key = gtk_label_new("Seleziona un metodo di sblocco o crea una chiave");
    gtk_box_append(GTK_BOX(box), status_key);
    
    return box;
}


// Creazione pagina per la Connessione fisica al server
GtkWidget* create_connect_page() {
    //Creazione di un box verticale per organizzare gli elementi della pagina
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER); gtk_widget_set_valign(box, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(box), gtk_label_new("Passo 3: Connessione al Server"));
    GtkWidget *btn = gtk_button_new_with_label("Stabilisci Tunnel mTLS");
    gtk_widget_add_css_class(btn, "suggested-action");
    gtk_widget_set_size_request(btn, 200, 50);
    g_signal_connect(btn, "clicked", G_CALLBACK(on_connect_clicked), NULL); //Quando cliccato, esegue la callback on_connect_clicked

    gtk_box_append(GTK_BOX(box), btn);
    status_connect = gtk_label_new("Pronto alla connessione sicura");
    gtk_box_append(GTK_BOX(box), status_connect);
    return box;
}

// Creazione della pagina del Vault!
GtkWidget* create_vault_page() {

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_widget_set_margin_top(box, 20); gtk_widget_set_margin_bottom(box, 20);
    gtk_widget_set_margin_start(box, 20); gtk_widget_set_margin_end(box, 20);
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span size='large' weight='bold'>Le tue Credenziali</span>");
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


GtkWidget* create_persistent_header() {
    // Un box orizzontale con padding
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_margin_start(header, 15);
    gtk_widget_set_margin_top(header, 10);
    gtk_widget_set_margin_bottom(header, 5);

    // Label per l'utente
    user_info_label = gtk_label_new("");
    gtk_widget_add_css_class(user_info_label, "user-badge"); 
    
    // Recuperiamo l'utente iniziale dal context tramite il service
    const char *current_user = client_service_get_username(); 
    char label_text[256];
    snprintf(label_text, sizeof(label_text), "Utente: %s", current_user);
    gtk_label_set_text(GTK_LABEL(user_info_label), label_text);

    gtk_box_append(GTK_BOX(header), user_info_label);
    
    return header;
}

GtkWidget* create_ca_setup_page() {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);

    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span size='large' weight='bold'>Passo 0: Verifica Autorità (CA)</span>");
    gtk_box_append(GTK_BOX(box), title);

    GtkWidget *desc = gtk_label_new("Per connettersi in sicurezza, il client necessita del certificato pubblico della CA.\n"
                                   "Seleziona il file 'ca.crt' che ti è stato fornito fuori dal canale di rete.");
    gtk_label_set_justify(GTK_LABEL(desc), GTK_JUSTIFY_CENTER);
    gtk_box_append(GTK_BOX(box), desc);

    GtkWidget *btn_import = gtk_button_new_with_label("Importa Certificato CA");
    gtk_widget_add_css_class(btn_import, "suggested-action");
    g_signal_connect(btn_import, "clicked", G_CALLBACK(on_import_ca_clicked), NULL);
    gtk_box_append(GTK_BOX(box), btn_import);

    status_ca = gtk_label_new("Stato: CA mancante");
    gtk_box_append(GTK_BOX(box), status_ca);

    return box;
}

void setup_main_window(GtkApplication *app) { 
    // 1. Creazione della finestra principale
    GtkWidget *window = gtk_application_window_new(app); 
    gtk_window_set_title(GTK_WINDOW(window), "KeyVault(amm) Client");
    gtk_window_set_default_size(GTK_WINDOW(window), 500, 500); // Aumentato leggermente per l'header

    // 2. CREAZIONE DEL CONTENITORE PRINCIPALE (Vertical Box)
    // Questo conterrà sia l'header fisso che lo stack variabile
    GtkWidget *main_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_window_set_child(GTK_WINDOW(window), main_vbox); 

    // 3. AGGIUNTA HEADER PERSISTENTE (Alto)
    // create_persistent_header() deve restituire un GtkWidget* con la label dell'utente
    gtk_box_append(GTK_BOX(main_vbox), create_persistent_header());

    // 4. CREAZIONE DELLO STACK (Basso - Navigabile)
    stack = gtk_stack_new(); 
    gtk_stack_set_transition_type(GTK_STACK(stack), GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    
    // Importante: diciamo allo stack di espandersi per occupare tutto lo spazio rimanente
    gtk_widget_set_vexpand(stack, TRUE);
    gtk_box_append(GTK_BOX(main_vbox), stack);

    // 5. REGISTRAZIONE DELLE PAGINE
    gtk_stack_add_named(GTK_STACK(stack), create_config_page(), "config_page");
    gtk_stack_add_named(GTK_STACK(stack), create_ca_setup_page(), "ca_page");
    gtk_stack_add_named(GTK_STACK(stack), create_intro_page(), "intro_page");
    gtk_stack_add_named(GTK_STACK(stack), create_enrollment_page(), "enroll_page");
    gtk_stack_add_named(GTK_STACK(stack), create_key_select_page(), "key_page");
    gtk_stack_add_named(GTK_STACK(stack), create_connect_page(), "connect_page");
    gtk_stack_add_named(GTK_STACK(stack), create_vault_page(), "vault_page");

    // 6. AVVIO
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "config_page"); 
    gtk_window_present(GTK_WINDOW(window)); 
}
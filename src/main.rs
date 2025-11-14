use eframe::egui;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use std::collections::HashMap;

mod types;
mod network;
mod storage;
mod crypto;
mod ui;

use types::*;
use network::NetworkManager;
use storage::StorageManager;

use crate::types::{GroupForm, AppSettings};

fn main() -> Result<(), eframe::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 900.0])
            .with_min_inner_size([1024.0, 700.0])
            .with_title("Private Messenger")
            .with_icon(load_icon()),
        ..Default::default()
    };
    
    eframe::run_native(
        "Private Messenger",
        options,
        Box::new(|cc| Ok(Box::new(MessengerApp::new(cc)))),
    )
}

fn load_icon() -> egui::IconData {
    // Default icon data
    egui::IconData {
        rgba: vec![255; 32 * 32 * 4],
        width: 32,
        height: 32,
    }
}

pub struct MessengerApp {
    // Core components
    runtime: tokio::runtime::Runtime,
    network: Arc<NetworkManager>,
    storage: Arc<RwLock<StorageManager>>,
    crypto: Arc<RwLock<crypto::CryptoManager>>,
    
    // Event channels
    event_tx: mpsc::UnboundedSender<AppEvent>,
    event_rx: Arc<RwLock<mpsc::UnboundedReceiver<AppEvent>>>,
    
    // Application state
    current_user: Option<User>,
    current_view: AppView,
    auth_view: AuthView,
    auth_form: AuthForm,
    settings: AppSettings,
    connection_state: ConnectionState,
    
    // Data
    chats: HashMap<String, Chat>,
    messages: HashMap<String, Vec<Message>>, // chat_id -> messages
    contacts: Vec<User>,
    active_call: Option<ActiveCall>,
    typing_indicators: HashMap<String, TypingIndicator>,
    
    // UI state
    selected_chat_id: Option<String>,
    message_input: HashMap<String, String>, // chat_id -> draft message
    search_query: String,
    show_settings: bool,
    show_profile: bool,
    show_create_group: bool,
    
    // File transfers
    file_transfers: HashMap<uuid::Uuid, FileTransfer>,
    
    // Notifications
    notifications: Vec<AppNotification>,
    toasts: egui_notify::Toasts,
    
    // Create group form
    group_form: GroupForm,
    
    // Scroll positions
    scroll_positions: HashMap<String, f32>,
}

impl MessengerApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        
        let settings = AppSettings::default();
        let storage = Arc::new(RwLock::new(
            StorageManager::new().expect("Failed to initialize storage")
        ));
        
        // Load saved settings
        let loaded_settings = runtime.block_on(async {
            storage.read().await.load_settings().await.unwrap_or_default()
        });
        
        let network = Arc::new(NetworkManager::new(
            loaded_settings.server_url.clone(),
            event_tx.clone(),
        ));
        
        let crypto = Arc::new(RwLock::new(
            crypto::CryptoManager::new()
        ));
        
        let mut app = Self {
            runtime,
            network,
            storage,
            crypto,
            event_tx,
            event_rx: Arc::new(RwLock::new(event_rx)),
            current_user: None,
            current_view: AppView::Auth,
            auth_view: AuthView::Login,
            auth_form: AuthForm::default(),
            settings: loaded_settings,
            connection_state: ConnectionState::default(),
            chats: HashMap::new(),
            messages: HashMap::new(),
            contacts: Vec::new(),
            active_call: None,
            typing_indicators: HashMap::new(),
            selected_chat_id: None,
            message_input: HashMap::new(),
            search_query: String::new(),
            show_settings: false,
            show_profile: false,
            show_create_group: false,
            file_transfers: HashMap::new(),
            notifications: Vec::new(),
            toasts: egui_notify::Toasts::default(),
            group_form: GroupForm::default(),
            scroll_positions: HashMap::new(),
        };
        
        // Try to auto-login if token exists
        app.try_auto_login();
        
        app
    }
    
    fn try_auto_login(&mut self) {
        let storage = self.storage.clone();
        let network = self.network.clone();
        let event_tx = self.event_tx.clone();
        
        self.runtime.spawn(async move {
            if let Ok(Some((token, user))) = storage.read().await.load_session().await {
                network.set_token(token.clone()).await;
                
                // Try to connect websocket
                if network.connect_websocket(&user.id).await.is_ok() {
                    let _ = event_tx.send(AppEvent::LoginSuccess(AuthResponse {
                        user,
                        token,
                    }));
                }
            }
        });
    }
    
    fn process_events(&mut self) {
        let mut events = Vec::new();
        
        if let Ok(mut rx) = self.event_rx.try_write() {
            while let Ok(event) = rx.try_recv() {
                events.push(event);
            }
        }
        
        for event in events {
            self.handle_event(event);
        }
    }
    
    fn handle_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Connected => {
                self.connection_state.connected = true;
                self.connection_state.connecting = false;
                self.connection_state.reconnecting = false;
                self.toasts.success("Connected to server");
                
                // Load initial data
                self.load_chats();
                self.load_contacts();
            }
            
            AppEvent::Disconnected => {
                self.connection_state.connected = false;
                self.toasts.warning("Disconnected from server");
                
                if self.settings.auto_reconnect {
                    self.attempt_reconnect();
                }
            }
            
            AppEvent::LoginSuccess(auth) => {
                self.current_user = Some(auth.user.clone());
                self.current_view = AppView::ChatList;
                self.auth_form = AuthForm::default();
                
                // Save session
                let storage = self.storage.clone();
                let token = auth.token.clone();
                let user = auth.user.clone();
                
                self.runtime.spawn(async move {
                    let _ = storage.write().await.save_session(&token, &user).await;
                });
                
                self.toasts.success(format!("Welcome, {}!", auth.user.display_name));
            }
            
            AppEvent::LoginError(err) => {
                self.auth_form.error = Some(err.clone());
                self.auth_form.loading = false;
                self.toasts.error(err);
            }
            
            AppEvent::RegisterSuccess(auth) => {
                self.current_user = Some(auth.user.clone());
                self.current_view = AppView::ChatList;
                self.auth_form = AuthForm::default();
                self.toasts.success("Account created successfully!");
            }
            
            AppEvent::RegisterError(err) => {
                self.auth_form.error = Some(err.clone());
                self.auth_form.loading = false;
                self.toasts.error(err);
            }
            
            AppEvent::ChatsLoaded(chats) => {
                for chat in chats {
                    self.chats.insert(chat.id.clone(), chat);
                }
            }
            
            AppEvent::MessagesLoaded(chat_id, messages) => {
                self.messages.insert(chat_id, messages);
            }
            
            AppEvent::MessageReceived(message) => {
                let chat_id = message.chat_id.clone();
                
                // Add to messages
                self.messages.entry(chat_id.clone())
                    .or_insert_with(Vec::new)
                    .push(message.clone());
                
                // Update chat last activity
                if let Some(chat) = self.chats.get_mut(&chat_id) {
                    chat.last_activity = message.timestamp;
                    chat.last_message = message.content.clone();
                    
                    // Increment unread if not currently viewing
                    if self.selected_chat_id.as_ref() != Some(&chat_id) {
                        let count = chat.unread_count.unwrap_or(0);
                        chat.unread_count = Some(count + 1);
                    }
                }
                
                // Show notification
                if self.settings.notifications_enabled {
                    if let Some(sender_name) = &message.sender_name {
                        self.show_notification(
                            sender_name.clone(),
                            message.content.clone().unwrap_or_else(|| "[Media]".to_string()),
                            NotificationType::Message,
                            Some(chat_id),
                        );
                    }
                }
            }
            
            AppEvent::ContactsLoaded(contacts) => {
                self.contacts = contacts;
            }
            
            AppEvent::UserStatusChanged(user_id, is_online) => {
                // Update user status in contacts
                if let Some(contact) = self.contacts.iter_mut().find(|c| c.id == user_id) {
                    contact.is_online = is_online;
                }
            }
            
            AppEvent::FileUploadComplete(id, url) => {
                if let Some(transfer) = self.file_transfers.get_mut(&id) {
                    transfer.completed = true;
                    transfer.progress = 1.0;
                    
                    // Send message with media URL
                    self.send_media_message(&transfer.chat_id, &url);
                }
            }
            
            AppEvent::Notification(notif) => {
                self.notifications.push(notif);
            }
            
            _ => {}
        }
    }
    
    fn load_chats(&mut self) {
        let network = self.network.clone();
        let event_tx = self.event_tx.clone();
        
        self.runtime.spawn(async move {
            match network.get_chats().await {
                Ok(chats) => {
                    let _ = event_tx.send(AppEvent::ChatsLoaded(chats));
                }
                Err(e) => {
                    tracing::error!("Failed to load chats: {}", e);
                }
            }
        });
    }
    
    fn load_contacts(&mut self) {
        let network = self.network.clone();
        let event_tx = self.event_tx.clone();
        
        self.runtime.spawn(async move {
            match network.get_contacts().await {
                Ok(contacts) => {
                    let _ = event_tx.send(AppEvent::ContactsLoaded(contacts));
                }
                Err(e) => {
                    tracing::error!("Failed to load contacts: {}", e);
                }
            }
        });
    }
    
    fn load_messages(&mut self, chat_id: &str) {
        let network = self.network.clone();
        let event_tx = self.event_tx.clone();
        let chat_id = chat_id.to_string();
        
        self.runtime.spawn(async move {
            match network.get_messages(&chat_id, Some(50), None).await {
                Ok(messages) => {
                    let _ = event_tx.send(AppEvent::MessagesLoaded(chat_id, messages));
                }
                Err(e) => {
                    tracing::error!("Failed to load messages: {}", e);
                }
            }
        });
    }
    
    fn send_message(&mut self, chat_id: &str, content: &str) {
        if let Some(current_user) = &self.current_user {
            let signal = SignalMessage {
                message_type: "send_message".to_string(),
                chat_id: Some(chat_id.to_string()),
                sender_id: Some(current_user.id.clone()),
                message_id: Some(uuid::Uuid::new_v4().to_string()),
                payload: Some(serde_json::json!({
                    "type": "text",
                    "content": content,
                })),
                jwt: None,
                ts: Some(chrono::Utc::now().timestamp()),
            };
            
            let network = self.network.clone();
            self.runtime.spawn(async move {
                let _ = network.send_signal(signal).await;
            });
            
            // Clear input
            self.message_input.remove(chat_id);
        }
    }
    
    fn send_media_message(&mut self, chat_id: &str, media_url: &str) {
        if let Some(current_user) = &self.current_user {
            let signal = SignalMessage {
                message_type: "send_message".to_string(),
                chat_id: Some(chat_id.to_string()),
                sender_id: Some(current_user.id.clone()),
                message_id: Some(uuid::Uuid::new_v4().to_string()),
                payload: Some(serde_json::json!({
                    "type": "image",
                    "media_url": media_url,
                })),
                jwt: None,
                ts: Some(chrono::Utc::now().timestamp()),
            };
            
            let network = self.network.clone();
            self.runtime.spawn(async move {
                let _ = network.send_signal(signal).await;
            });
        }
    }
    
    fn attempt_reconnect(&mut self) {
        if self.connection_state.reconnect_attempts >= self.settings.max_reconnect_attempts {
            self.toasts.error("Max reconnection attempts reached");
            return;
        }
        
        self.connection_state.reconnecting = true;
        self.connection_state.reconnect_attempts += 1;
        
        if let Some(user) = &self.current_user {
            let network = self.network.clone();
            let user_id = user.id.clone();
            
            self.runtime.spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                let _ = network.connect_websocket(&user_id).await;
            });
        }
    }
    
    fn show_notification(&mut self, title: String, message: String, typ: NotificationType, chat_id: Option<String>) {
        let notif = AppNotification {
            id: uuid::Uuid::new_v4(),
            title: title.clone(),
            message: message.clone(),
            notification_type: typ,
            timestamp: chrono::Utc::now(),
            read: false,
            action_chat_id: chat_id,
        };
        
        self.notifications.push(notif);
        
        // Also show toast
        self.toasts.info(format!("{}: {}", title, message));
    }
    
    fn logout(&mut self) {
        self.current_user = None;
        self.current_view = AppView::Auth;
        self.chats.clear();
        self.messages.clear();
        self.contacts.clear();
        
        let storage = self.storage.clone();
        self.runtime.spawn(async move {
            let _ = storage.write().await.clear_session().await;
        });
        
        self.toasts.info("Logged out successfully");
    }
}

impl eframe::App for MessengerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Process events
        self.process_events();

        // Apply custom styling
        self.apply_custom_style(ctx);

        // Show appropriate view based on authentication state
        match &self.current_view {
            AppView::Auth => {
                // Use the auth UI module
                ui::auth::show_auth_ui(self, ctx);
            }
            _ => {
                // Use the main UI layout module
                ui::main::show_main_layout(self, ctx);
            }
        }

        // Show toasts
        self.toasts.show(ctx);

        // Request repaint for animations
        ctx.request_repaint();
    }
}

impl MessengerApp {
    fn apply_custom_style(&self, ctx: &egui::Context) {
        let mut style = (*ctx.style()).clone();
        
        // Modern rounded corners
        style.visuals.window_rounding = egui::Rounding::same(12.0);
        style.visuals.menu_rounding = egui::Rounding::same(8.0);
        
        // Adjust spacing for compact/normal mode
        if self.settings.compact_mode {
            style.spacing.item_spacing = egui::vec2(6.0, 4.0);
            style.spacing.button_padding = egui::vec2(6.0, 3.0);
        } else {
            style.spacing.item_spacing = egui::vec2(10.0, 8.0);
            style.spacing.button_padding = egui::vec2(12.0, 6.0);
        }
        
        // Font size
        style.text_styles.insert(
            egui::TextStyle::Body,
            egui::FontId::proportional(self.settings.font_size),
        );
        
        ctx.set_style(style);
    }
}

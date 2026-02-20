use crate::types::*;
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage, MaybeTlsStream, WebSocketStream};
use url::Url;

// ============================================================================
// NETWORK MANAGER
// ============================================================================

pub struct NetworkManager {
    base_url: String,
    ws_url: String,
    token: Option<String>,
    ws_connection: Arc<RwLock<Option<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>>>>,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    connected: Arc<RwLock<bool>>,
    reconnect_attempts: Arc<RwLock<u32>>,
}

impl NetworkManager {
    pub fn new(base_url: String, event_tx: mpsc::UnboundedSender<AppEvent>) -> Self {
        let ws_url = base_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        
        Self {
            base_url,
            ws_url,
            token: None,
            ws_connection: Arc::new(RwLock::new(None)),
            event_tx,
            connected: Arc::new(RwLock::new(false)),
            reconnect_attempts: Arc::new(RwLock::new(0)),
        }
    }

    // ============================================================================
    // AUTHENTICATION
    // ============================================================================

    pub async fn register(&mut self, username: &str, password: &str, display_name: &str, phone_number: Option<&str>) -> Result<AuthResponse> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/register", self.base_url);
        
        let request = json!({
            "username": username,
            "password": password,
            "display_name": display_name,
            "phone_number": phone_number.unwrap_or(""),
        });

        let response = client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send registration request")?;

        if response.status().is_success() {
            let auth_response: AuthResponse = response.json().await.context("Failed to parse registration response")?;
            self.token = Some(auth_response.token.clone());
            Ok(auth_response)
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(anyhow::anyhow!("Registration failed: {}", error_text))
        }
    }

    pub async fn login(&mut self, username: &str, password: &str) -> Result<AuthResponse> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/login", self.base_url);
        
        let request = json!({
            "username": username,
            "password": password,
        });

        let response = client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send login request")?;

        if response.status().is_success() {
            let auth_response: AuthResponse = response.json().await.context("Failed to parse login response")?;
            self.token = Some(auth_response.token.clone());
            Ok(auth_response)
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(anyhow::anyhow!("Login failed: {}", error_text))
        }
    }

    pub async fn set_token(&mut self, token: String) {
        self.token = Some(token);
    }

    // ============================================================================
    // WEBSOCKET CONNECTION MANAGEMENT
    // ============================================================================

pub async fn connect_websocket(&self, user_id: &str) -> Result<()> {
    let token = self.token.as_ref().context("No authentication token available")?;
    
    let ws_url = format!(
        "{}/ws?user_id={}&token={}",
        self.ws_url, user_id, token
    );

    let (ws_stream, _) = connect_async(ws_url)
        .await
        .context("Failed to connect to WebSocket")?;

        {
            let mut conn = self.ws_connection.write().await;
            *conn = Some(ws_stream);
        }

        {
            let mut connected = self.connected.write().await;
            *connected = true;
        }

        {
            let mut attempts = self.reconnect_attempts.write().await;
            *attempts = 0;
        }

        // Start message processing
        self.start_message_processing().await;
        
        let _ = self.event_tx.send(AppEvent::Connected);
        
        tracing::info!("WebSocket connected successfully");
        Ok(())
    }

    pub async fn disconnect(&self) -> Result<()> {
        {
            let mut conn = self.ws_connection.write().await;
            if let Some(mut ws) = conn.take() {
    let _ = ws.close(None).await;
}
        }

        {
            let mut connected = self.connected.write().await;
            *connected = false;
        }

        let _ = self.event_tx.send(AppEvent::Disconnected);
        tracing::info!("WebSocket disconnected");
        Ok(())
    }

    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    // ============================================================================
    // MESSAGE PROCESSING
    // ============================================================================

    async fn start_message_processing(&self) {
        let ws_connection = self.ws_connection.clone();
        let event_tx = self.event_tx.clone();
        let connected = self.connected.clone();

        tokio::spawn(async move {
            loop {
                let message = {
                    let mut conn = ws_connection.write().await;
                    match conn.as_mut() {
                        Some(ws) => {
                            match ws.next().await {
                                Some(Ok(msg)) => Some(msg),
                                Some(Err(e)) => {
                                    tracing::error!("WebSocket error: {}", e);
                                    None
                                }
                                None => None,
                            }
                        }
                        None => {
                            // Connection closed
                            break;
                        }
                    }
                };

                if let Some(msg) = message {
                    if let WsMessage::Text(text) = msg {
                        if let Err(e) = Self::process_incoming_message(&text, &event_tx).await {
                            tracing::error!("Failed to process message: {}", e);
                        }
                    }
                } else {
                    // Connection lost
                    let mut conn_status = connected.write().await;
                    *conn_status = false;
                    let _ = event_tx.send(AppEvent::Disconnected);
                    break;
                }
            }
        });
    }

    async fn process_incoming_message(text: &str, event_tx: &mpsc::UnboundedSender<AppEvent>) -> Result<()> {
        let signal_msg: SignalMessage = serde_json::from_str(text)
            .context("Failed to parse SignalMessage")?;

        match signal_msg.message_type.as_str() {
            "message_received" => {
                if let Some(payload) = signal_msg.payload {
                    let message: Message = serde_json::from_value(payload)
                        .context("Failed to parse Message from payload")?;
                    let _ = event_tx.send(AppEvent::MessageReceived(message));
                }
            }
            "user_status_changed" => {
                if let Some(payload) = signal_msg.payload {
                    if let (Some(user_id), Some(is_online)) = (
                        payload.get("user_id").and_then(|v| v.as_str()),
                        payload.get("is_online").and_then(|v| v.as_bool()),
                    ) {
                        let _ = event_tx.send(AppEvent::UserStatusChanged(
                            user_id.to_string(),
                            is_online,
                        ));
                    }
                }
            }
            "typing_indicator" => {
                if let Some(payload) = signal_msg.payload {
                    if let (Some(chat_id), Some(user_id), Some(typing)) = (
                        payload.get("chat_id").and_then(|v| v.as_str()),
                        payload.get("user_id").and_then(|v| v.as_str()),
                        payload.get("typing").and_then(|v| v.as_bool()),
                    ) {
                        let _ = event_tx.send(AppEvent::TypingIndicator(
                            chat_id.to_string(),
                            user_id.to_string(),
                            typing,
                        ));
                    }
                }
            }
            "call_offer" => {
                if let Some(payload) = signal_msg.payload {
                    if let (Some(chat_id), Some(caller_id), Some(call_type_str)) = (
                        payload.get("chat_id").and_then(|v| v.as_str()),
                        payload.get("caller_id").and_then(|v| v.as_str()),
                        payload.get("call_type").and_then(|v| v.as_str()),
                    ) {
                        let call_type = match call_type_str {
                            "video" => CallType::Video,
                            _ => CallType::Voice,
                        };
                        let _ = event_tx.send(AppEvent::CallIncoming(
                            chat_id.to_string(),
                            caller_id.to_string(),
                            call_type,
                        ));
                    }
                }
            }
            "call_end" => {
                if let Some(payload) = signal_msg.payload {
                    if let (Some(call_id), Some(duration)) = (
                        payload.get("call_id").and_then(|v| v.as_str()),
                        payload.get("duration").and_then(|v| v.as_i64()),
                    ) {
                        let _ = event_tx.send(AppEvent::CallEnded(
                            call_id.to_string(),
                            duration as i32,
                        ));
                    }
                }
            }
            _ => {
                tracing::debug!("Unknown message type: {}", signal_msg.message_type);
            }
        }

        Ok(())
    }

    // ============================================================================
    // MESSAGE SENDING
    // ============================================================================

    pub async fn send_signal(&self, signal: SignalMessage) -> Result<()> {
        let message_json = serde_json::to_string(&signal)
            .context("Failed to serialize SignalMessage")?;

        let mut conn = self.ws_connection.write().await;
        match conn.as_mut() {
            Some(ws) => {
                ws.send(WsMessage::Text(message_json)).await
                    .context("Failed to send WebSocket message")?;
                Ok(())
            }
            None => Err(anyhow::anyhow!("WebSocket not connected")),
        }
    }

    pub async fn send_message(&self, chat_id: &str, content: &str, message_type: MessageType) -> Result<()> {
        let message_id = uuid::Uuid::new_v4().to_string();
        
        let payload = json!({
            "type": match message_type {
                MessageType::Text => "text",
                MessageType::Image => "image",
                MessageType::Voice => "voice",
                MessageType::Video => "video",
                MessageType::File => "file",
                _ => "text",
            },
            "content": content,
        });

        let signal = SignalMessage {
            message_type: "send_message".to_string(),
            chat_id: Some(chat_id.to_string()),
            sender_id: None, // Will be set by server based on token
            message_id: Some(message_id),
            payload: Some(payload),
            jwt: self.token.clone(),
            ts: Some(chrono::Utc::now().timestamp()),
        };

        self.send_signal(signal).await
    }

    pub async fn send_typing_indicator(&self, chat_id: &str, is_typing: bool) -> Result<()> {
        let payload = json!({
            "chat_id": chat_id,
            "typing": is_typing,
        });

        let signal = SignalMessage {
            message_type: "typing_indicator".to_string(),
            chat_id: Some(chat_id.to_string()),
            sender_id: None,
            message_id: Some(uuid::Uuid::new_v4().to_string()),
            payload: Some(payload),
            jwt: self.token.clone(),
            ts: Some(chrono::Utc::now().timestamp()),
        };

        self.send_signal(signal).await
    }

    pub async fn send_call_offer(&self, chat_id: &str, call_type: CallType, sdp_offer: serde_json::Value) -> Result<()> {
        let payload = json!({
            "chat_id": chat_id,
            "call_type": match call_type {
                CallType::Voice => "voice",
                CallType::Video => "video",
            },
            "sdp_offer": sdp_offer,
        });

        let signal = SignalMessage {
            message_type: "call_offer".to_string(),
            chat_id: Some(chat_id.to_string()),
            sender_id: None,
            message_id: Some(uuid::Uuid::new_v4().to_string()),
            payload: Some(payload),
            jwt: self.token.clone(),
            ts: Some(chrono::Utc::now().timestamp()),
        };

        self.send_signal(signal).await
    }

    pub async fn send_call_answer(&self, call_id: &str, sdp_answer: serde_json::Value) -> Result<()> {
        let payload = json!({
            "call_id": call_id,
            "sdp_answer": sdp_answer,
        });

        let signal = SignalMessage {
            message_type: "call_answer".to_string(),
            chat_id: None,
            sender_id: None,
            message_id: Some(uuid::Uuid::new_v4().to_string()),
            payload: Some(payload),
            jwt: self.token.clone(),
            ts: Some(chrono::Utc::now().timestamp()),
        };

        self.send_signal(signal).await
    }

    pub async fn send_ice_candidate(&self, call_id: &str, candidate: serde_json::Value) -> Result<()> {
        let payload = json!({
            "call_id": call_id,
            "candidate": candidate,
        });

        let signal = SignalMessage {
            message_type: "ice_candidate".to_string(),
            chat_id: None,
            sender_id: None,
            message_id: Some(uuid::Uuid::new_v4().to_string()),
            payload: Some(payload),
            jwt: self.token.clone(),
            ts: Some(chrono::Utc::now().timestamp()),
        };

        self.send_signal(signal).await
    }

    // ============================================================================
    // HTTP API METHODS
    // ============================================================================

    pub async fn get_chats(&self) -> Result<Vec<Chat>> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/chats", self.base_url);

        let response = client
            .get(&url)
            .bearer_auth(self.token.as_ref().context("No token")?)
            .send()
            .await
            .context("Failed to fetch chats")?;

        if response.status().is_success() {
            let chats: Vec<Chat> = response.json().await.context("Failed to parse chats")?;
            Ok(chats)
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(anyhow::anyhow!("Failed to get chats: {}", error_text))
        }
    }

    pub async fn get_messages(&self, chat_id: &str, limit: Option<usize>, before: Option<String>) -> Result<Vec<Message>> {
        let client = reqwest::Client::new();
        let mut url = format!("{}/api/messages?chat_id={}", self.base_url, chat_id);

        if let Some(limit) = limit {
            url.push_str(&format!("&limit={}", limit));
        }
        if let Some(before) = before {
            url.push_str(&format!("&before={}", before));
        }

        let response = client
            .get(&url)
            .bearer_auth(self.token.as_ref().context("No token")?)
            .send()
            .await
            .context("Failed to fetch messages")?;

        if response.status().is_success() {
            let messages: Vec<Message> = response.json().await.context("Failed to parse messages")?;
            Ok(messages)
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(anyhow::anyhow!("Failed to get messages: {}", error_text))
        }
    }

    pub async fn get_contacts(&self) -> Result<Vec<User>> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/contacts", self.base_url);

        let response = client
            .get(&url)
            .bearer_auth(self.token.as_ref().context("No token")?)
            .send()
            .await
            .context("Failed to fetch contacts")?;

        if response.status().is_success() {
            let contacts: Vec<User> = response.json().await.context("Failed to parse contacts")?;
            Ok(contacts)
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(anyhow::anyhow!("Failed to get contacts: {}", error_text))
        }
    }

    pub async fn add_contact(&self, contact_id: &str, display_name: Option<&str>) -> Result<()> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/contacts/add", self.base_url);

        let request = json!({
            "contact_id": contact_id,
            "display_name": display_name.unwrap_or(""),
        });

        let response = client
            .post(&url)
            .bearer_auth(self.token.as_ref().context("No token")?)
            .json(&request)
            .send()
            .await
            .context("Failed to add contact")?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(anyhow::anyhow!("Failed to add contact: {}", error_text))
        }
    }

    pub async fn create_group(&self, title: &str, description: &str, member_ids: Vec<String>) -> Result<Chat> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/groups", self.base_url);

        let request = json!({
            "title": title,
            "description": description,
            "member_ids": member_ids,
        });

        let response = client
            .post(&url)
            .bearer_auth(self.token.as_ref().context("No token")?)
            .json(&request)
            .send()
            .await
            .context("Failed to create group")?;

        if response.status().is_success() {
            let chat: Chat = response.json().await.context("Failed to parse group chat")?;
            Ok(chat)
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(anyhow::anyhow!("Failed to create group: {}", error_text))
        }
    }

    pub async fn update_profile(&self, display_name: Option<&str>, status: Option<&str>, avatar_url: Option<&str>) -> Result<()> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/profile", self.base_url);

        let mut request = serde_json::Map::new();
        if let Some(name) = display_name {
            request.insert("display_name".to_string(), json!(name));
        }
        if let Some(status_text) = status {
            request.insert("status".to_string(), json!(status_text));
        }
        if let Some(avatar) = avatar_url {
            request.insert("avatar_url".to_string(), json!(avatar));
        }

        let response = client
            .put(&url)
            .bearer_auth(self.token.as_ref().context("No token")?)
            .json(&request)
            .send()
            .await
            .context("Failed to update profile")?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(anyhow::anyhow!("Failed to update profile: {}", error_text))
        }
    }

    // ============================================================================
    // FILE UPLOAD
    // ============================================================================

pub async fn upload_file(&self, file_path: &str, chat_id: &str) -> Result<FileTransfer> {
    let client = reqwest::Client::new();
    let url = format!("{}/api/upload", self.base_url);

    let file = tokio::fs::read(file_path).await
        .context("Failed to read file")?;
    
    let file_name = std::path::Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();

    let file_size = file.len() as u64;

    let form = reqwest::multipart::Form::new()
        .text("chat_id", chat_id.to_string())
        .part("file", reqwest::multipart::Part::bytes(file)
            .file_name(file_name.clone()));

    let response = client
        .post(&url)
        .bearer_auth(self.token.as_ref().context("No token")?)
        .multipart(form)
        .send()
        .await
        .context("Failed to upload file")?;

    if response.status().is_success() {
        let upload_response: serde_json::Value = response.json().await
            .context("Failed to parse upload response")?;

        let media_url = upload_response.get("media_url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .context("No media URL in response")?;

        let transfer = FileTransfer {
            id: uuid::Uuid::new_v4(),
            chat_id: chat_id.to_string(),
            file_name,
            file_size,
            file_type: "file".to_string(),
            progress: 1.0,
            completed: true,
            error: None,
            local_path: Some(file_path.to_string()),
            remote_url: Some(media_url),
        };

        Ok(transfer)
    } else {
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        Err(anyhow::anyhow!("File upload failed: {}", error_text))
    }
}

    // ============================================================================
    // RECONNECTION LOGIC
    // ============================================================================

    pub async fn attempt_reconnect(&self, user_id: &str) -> bool {
        let mut attempts = self.reconnect_attempts.write().await;
        *attempts += 1;

        if *attempts > 5 {
            tracing::error!("Max reconnection attempts reached");
            return false;
        }

        tracing::info!("Attempting to reconnect (attempt {})", *attempts);
        
        match self.connect_websocket(user_id).await {
            Ok(()) => {
                *attempts = 0;
                true
            }
            Err(e) => {
                tracing::error!("Reconnection failed: {}", e);
                false
            }
        }
    }

    pub async fn get_connection_state(&self) -> ConnectionState {
        ConnectionState {
            connected: *self.connected.read().await,
            connecting: false, // You might want to track this separately
            reconnecting: *self.reconnect_attempts.read().await > 0,
            reconnect_attempts: *self.reconnect_attempts.read().await,
        }
    }
}

// ============================================================================
// ASYNC UTILITIES
// ============================================================================

impl NetworkManager {
    pub async fn start_periodic_ping(&self) {
        let ws_connection = self.ws_connection.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                let mut conn = ws_connection.write().await;
                if let Some(ws) = conn.as_mut() {
                    let ping_msg = WsMessage::Ping(vec![]);
                    if let Err(e) = ws.send(ping_msg).await {
                        tracing::error!("Failed to send ping: {}", e);
                        break;
                    }
                } else {
                    break;
                }
            }
        });
    }
}
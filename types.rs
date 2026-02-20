use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ============================================================================
// USER & AUTHENTICATION TYPES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub phone_number: Option<String>,
    pub status: String,
    pub avatar_url: Option<String>,
    pub last_seen: DateTime<Utc>,
    pub is_online: bool,
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub user: User,
    pub token: String,
}

#[derive(Debug, Clone, Default)]
pub struct AuthForm {
    pub username: String,
    pub password: String,
    pub display_name: String,
    pub phone_number: String,
    pub loading: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthView {
    Login,
    Register,
}

// ============================================================================
// CHAT & MESSAGE TYPES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chat {
    pub id: String,
    pub r#type: ChatType,
    pub title: String,
    pub description: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub last_message: Option<String>,
    pub avatar_url: Option<String>,
    pub members: Vec<ChatMember>,
    pub admins: Vec<String>,
    pub participant_ids: Vec<String>,
    pub unread_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChatType {
    Private,
    Group,
}

impl Default for ChatType {
    fn default() -> Self {
        ChatType::Private
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMember {
    pub user_id: String,
    pub joined_at: DateTime<Utc>,
    pub role: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub chat_id: String,
    pub sender_id: String,
    pub sender_name: Option<String>,
    pub r#type: MessageType,
    pub content: Option<String>,
    pub media_url: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub edited: bool,
    pub edited_at: Option<DateTime<Utc>>,
    pub reply_to: Option<String>,
    pub encrypted: bool,
    pub call_metadata: Option<CallMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessageType {
    Text,
    Image,
    Voice,
    Video,
    File,
    CallOffer,
    CallAnswer,
    ICECandidate,
    CallEnd,
    System,
}

impl Default for MessageType {
    fn default() -> Self {
        MessageType::Text
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallMetadata {
    pub call_type: CallType,
    pub call_id: String,
    pub sdp_offer: Option<serde_json::Value>,
    pub sdp_answer: Option<serde_json::Value>,
    pub ice_candidates: Vec<serde_json::Value>,
    pub duration: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CallType {
    Voice,
    Video,
}

// ============================================================================
// APPLICATION STATE TYPES
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum AppView {
    Auth,
    ChatList,
    Chat,
    Contacts,
    Settings,
}

impl Default for AppView {
    fn default() -> Self {
        AppView::Auth
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub theme: Theme,
    pub notifications_enabled: bool,
    pub sound_enabled: bool,
    pub auto_download: bool,
    pub compact_mode: bool,
    pub font_size: f32,
    pub server_url: String,
    pub auto_reconnect: bool,
    pub max_reconnect_attempts: u32,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: Theme::Dark,
            notifications_enabled: true,
            sound_enabled: true,
            auto_download: true,
            compact_mode: false,
            font_size: 14.0,
            server_url: "https://localhost:8443".to_string(),
            auto_reconnect: true,
            max_reconnect_attempts: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Theme {
    Light,
    Dark,
    System,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionState {
    pub connected: bool,
    pub connecting: bool,
    pub reconnecting: bool,
    pub reconnect_attempts: u32,
}

// ============================================================================
// EVENT & NOTIFICATION TYPES
// ============================================================================

#[derive(Debug, Clone)]
pub enum AppEvent {
    // Connection events
    Connected,
    Disconnected,
    Reconnecting,
    
    // Authentication events
    LoginSuccess(AuthResponse),
    LoginError(String),
    RegisterSuccess(AuthResponse),
    RegisterError(String),
    Logout,
    
    // Data loading events
    ChatsLoaded(Vec<Chat>),
    MessagesLoaded(String, Vec<Message>),
    ContactsLoaded(Vec<User>),
    
    // Real-time events
    MessageReceived(Message),
    MessageSent(Message),
    UserStatusChanged(String, bool),
    TypingIndicator(String, String, bool), // chat_id, user_id, typing
    
    // Call events
    CallIncoming(String, String, CallType), // chat_id, caller_id, call_type
    CallAccepted(String),
    CallRejected(String),
    CallEnded(String, i32), // call_id, duration
    
    // File transfer events
    FileUploadProgress(Uuid, f32),
    FileUploadComplete(Uuid, String), // id, url
    FileDownloadProgress(Uuid, f32),
    FileDownloadComplete(Uuid, String), // id, local_path
    
    // Notification events
    Notification(AppNotification),
    
    // UI events
    ChatSelected(String),
    ChatCreated(Chat),
    ContactAdded(User),
}

#[derive(Debug, Clone)]
pub struct AppNotification {
    pub id: Uuid,
    pub title: String,
    pub message: String,
    pub notification_type: NotificationType,
    pub timestamp: DateTime<Utc>,
    pub read: bool,
    pub action_chat_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NotificationType {
    Message,
    Call,
    System,
    Error,
    Success,
    Warning,
    Info,
}

// ============================================================================
// LIVE INTERACTION TYPES
// ============================================================================

#[derive(Debug, Clone)]
pub struct TypingIndicator {
    pub user_id: String,
    pub user_name: String,
    pub chat_id: String,
    pub is_typing: bool,
    pub last_activity: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct FileTransfer {
    pub id: Uuid,
    pub chat_id: String,
    pub file_name: String,
    pub file_size: u64,
    pub file_type: String,
    pub progress: f32,
    pub completed: bool,
    pub error: Option<String>,
    pub local_path: Option<String>,
    pub remote_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ActiveCall {
    pub call_id: String,
    pub chat_id: String,
    pub call_type: CallType,
    pub initiator_id: String,
    pub participants: HashMap<String, bool>, // user_id -> joined
    pub start_time: DateTime<Utc>,
    pub connected: bool,
    pub local_stream: Option<String>, // Placeholder for media stream ID
    pub remote_stream: Option<String>, // Placeholder for media stream ID
}

// ============================================================================
// NETWORK & ENCRYPTION TYPES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalMessage {
    pub message_type: String,
    pub chat_id: Option<String>,
    pub sender_id: Option<String>,
    pub message_id: Option<String>,
    pub payload: Option<serde_json::Value>,
    pub jwt: Option<String>,
    pub ts: Option<i64>,
}

// ============================================================================
// UI FORM TYPES
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct GroupForm {
    pub title: String,
    pub description: String,
    pub selected_members: Vec<String>,
    pub error: Option<String>,
}

// ============================================================================
// IMPLEMENTATIONS FOR SERDE
// ============================================================================

// Manual Serialize/Deserialize implementations for types that need it
impl Serialize for AppEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // For now, we'll just serialize a string representation
        // In a real implementation, you'd want proper serialization
        match self {
            AppEvent::Connected => serializer.serialize_str("Connected"),
            AppEvent::Disconnected => serializer.serialize_str("Disconnected"),
            AppEvent::LoginSuccess(_) => serializer.serialize_str("LoginSuccess"),
            AppEvent::LoginError(_) => serializer.serialize_str("LoginError"),
            _ => serializer.serialize_str("AppEvent"),
        }
    }
}

impl<'de> Deserialize<'de> for AppEvent {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // This is a simplified implementation
        // In practice, you'd want proper deserialization
        Ok(AppEvent::Connected)
    }
}

// Implement Serialize for other types that might need network transmission
impl Serialize for TypingIndicator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("TypingIndicator", 5)?;
        state.serialize_field("user_id", &self.user_id)?;
        state.serialize_field("user_name", &self.user_name)?;
        state.serialize_field("chat_id", &self.chat_id)?;
        state.serialize_field("is_typing", &self.is_typing)?;
        state.serialize_field("last_activity", &self.last_activity.timestamp())?;
        state.end()
    }
}

// ============================================================================
// CONVENIENCE TRAIT IMPLEMENTATIONS
// ============================================================================

impl Default for ActiveCall {
    fn default() -> Self {
        Self {
            call_id: Uuid::new_v4().to_string(),
            chat_id: String::new(),
            call_type: CallType::Voice,
            initiator_id: String::new(),
            participants: HashMap::new(),
            start_time: Utc::now(),
            connected: false,
            local_stream: None,
            remote_stream: None,
        }
    }
}

impl Default for TypingIndicator {
    fn default() -> Self {
        Self {
            user_id: String::new(),
            user_name: String::new(),
            chat_id: String::new(),
            is_typing: false,
            last_activity: Utc::now(),
        }
    }
}

impl Default for FileTransfer {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            chat_id: String::new(),
            file_name: String::new(),
            file_size: 0,
            file_type: String::new(),
            progress: 0.0,
            completed: false,
            error: None,
            local_path: None,
            remote_url: None,
        }
    }
}

impl Default for AppNotification {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            title: String::new(),
            message: String::new(),
            notification_type: NotificationType::Message,
            timestamp: Utc::now(),
            read: false,
            action_chat_id: None,
        }
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

impl Chat {
    pub fn is_private(&self) -> bool {
        matches!(self.r#type, ChatType::Private)
    }
    
    pub fn is_group(&self) -> bool {
        matches!(self.r#type, ChatType::Group)
    }
    
    pub fn get_other_participant(&self, current_user_id: &str) -> Option<String> {
        if self.is_private() {
            self.participant_ids
                .iter()
                .find(|&id| id != current_user_id)
                .cloned()
        } else {
            None
        }
    }
}

impl Message {
    pub fn is_text(&self) -> bool {
        matches!(self.r#type, MessageType::Text)
    }
    
    pub fn is_media(&self) -> bool {
        matches!(
            self.r#type,
            MessageType::Image | MessageType::Voice | MessageType::Video | MessageType::File
        )
    }
    
    pub fn is_call(&self) -> bool {
        matches!(
            self.r#type,
            MessageType::CallOffer | MessageType::CallAnswer | MessageType::CallEnd
        )
    }
}

impl AppNotification {
    pub fn new(title: String, message: String, notification_type: NotificationType) -> Self {
        Self {
            id: Uuid::new_v4(),
            title,
            message,
            notification_type,
            timestamp: Utc::now(),
            read: false,
            action_chat_id: None,
        }
    }
    
    pub fn simple_message(sender: &str, content: &str, chat_id: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: format!("New message from {}", sender),
            message: content.to_string(),
            notification_type: NotificationType::Message,
            timestamp: Utc::now(),
            read: false,
            action_chat_id: chat_id,
        }
    }
}
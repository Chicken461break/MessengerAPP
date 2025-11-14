use egui::{Ui, ComboBox, Slider, Color32, RichText, Grid, ScrollArea};
use std::collections::HashMap;

#[derive(Debug, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum Theme {
    Light,
    Dark,
    System,
}

#[derive(Debug, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum MessageFont {
    System,
    Inter,
    Roboto,
    OpenSans,
    Monospace,
}

#[derive(Debug, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum MessageDensity {
    Comfortable,
    Compact,
    Cozy,
}

#[derive(Debug, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum VideoQuality {
    Low,    // 480p
    Medium, // 720p
    High,   // 1080p
    HD,     // 1440p
}

#[derive(Debug, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum AudioQuality {
    Low,    // 8kHz
    Medium, // 16kHz
    High,   // 32kHz
    HD,     // 48kHz
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrivacySettings {
    pub read_receipts: bool,
    pub typing_indicators: bool,
    pub online_status: bool,
    pub last_seen: bool,
    pub profile_photo: PrivacyLevel,
    pub add_by_phone: bool,
    pub block_unknown: bool,
    pub encrypted_backups: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum PrivacyLevel {
    Everyone,
    Contacts,
    Nobody,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NotificationSettings {
    pub enabled: bool,
    pub sound: bool,
    pub vibration: bool,
    pub preview: bool,
    pub group_notifications: bool,
    pub priority: NotificationPriority,
    pub quiet_hours: Option<(u8, u8)>, // (start_hour, end_hour)
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum NotificationPriority {
    Low,
    Medium,
    High,
    Urgent,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MediaSettings {
    pub auto_download: AutoDownloadLevel,
    pub video_quality: VideoQuality,
    pub audio_quality: AudioQuality,
    pub image_quality: u8, // 0-100
    pub save_to_gallery: bool,
    pub use_less_data: bool,
    pub stream_videos: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AutoDownloadLevel {
    Never,
    WiFIOnly,
    PhotosOnly,
    MediaOnly,
    All,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChatSettings {
    pub enter_sends: bool,
    pub font: MessageFont,
    pub density: MessageDensity,
    pub background_color: Option<Color32>,
    pub bubble_color: Option<Color32>,
    pub show_avatars: bool,
    pub show_timestamps: bool,
    pub show_emojis: bool,
    pub markdown_support: bool,
    pub auto_play_gifs: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CallSettings {
    pub noise_suppression: bool,
    pub echo_cancellation: bool,
    pub auto_answer: bool,
    pub ringtone: String,
    pub vibration_on_call: bool,
    pub low_data_usage: bool,
    pub video_bitrate: u32, // kbps
    pub audio_bitrate: u32, // kbps
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageSettings {
    pub auto_cleanup: bool,
    pub cleanup_after_days: u32,
    pub max_cache_size: u64, // MB
    pub backup_interval: u32, // days
    pub encrypt_local_files: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SettingsState {
    // Appearance
    pub theme: Theme,
    pub font_size: f32,
    pub custom_accent_color: Option<Color32>,
    
    // Notifications
    pub notifications: NotificationSettings,
    
    // Privacy
    pub privacy: PrivacySettings,
    
    // Media
    pub media: MediaSettings,
    
    // Chat
    pub chat: ChatSettings,
    
    // Calls
    pub calls: CallSettings,
    
    // Storage
    pub storage: StorageSettings,
    
    // Advanced
    pub auto_start: bool,
    pub hardware_acceleration: bool,
    pub developer_mode: bool,
    pub analytics_enabled: bool,
    
    // Network
    pub server_url: String,
    pub use_proxy: bool,
    pub proxy_url: Option<String>,
    
    // Experimental features
    pub experimental_features: HashMap<String, bool>,
}

impl Default for SettingsState {
    fn default() -> Self {
        Self {
            theme: Theme::Dark,
            font_size: 14.0,
            custom_accent_color: None,
            
            notifications: NotificationSettings {
                enabled: true,
                sound: true,
                vibration: true,
                preview: true,
                group_notifications: true,
                priority: NotificationPriority::Medium,
                quiet_hours: None,
            },
            
            privacy: PrivacySettings {
                read_receipts: true,
                typing_indicators: true,
                online_status: true,
                last_seen: true,
                profile_photo: PrivacyLevel::Everyone,
                add_by_phone: true,
                block_unknown: false,
                encrypted_backups: true,
            },
            
            media: MediaSettings {
                auto_download: AutoDownloadLevel::WiFIOnly,
                video_quality: VideoQuality::High,
                audio_quality: AudioQuality::High,
                image_quality: 85,
                save_to_gallery: true,
                use_less_data: false,
                stream_videos: true,
            },
            
            chat: ChatSettings {
                enter_sends: true,
                font: MessageFont::System,
                density: MessageDensity::Comfortable,
                background_color: None,
                bubble_color: None,
                show_avatars: true,
                show_timestamps: true,
                show_emojis: true,
                markdown_support: true,
                auto_play_gifs: true,
            },
            
            calls: CallSettings {
                noise_suppression: true,
                echo_cancellation: true,
                auto_answer: false,
                ringtone: "default".to_string(),
                vibration_on_call: true,
                low_data_usage: false,
                video_bitrate: 2000,
                audio_bitrate: 128,
            },
            
            storage: StorageSettings {
                auto_cleanup: true,
                cleanup_after_days: 30,
                max_cache_size: 1024, // 1GB
                backup_interval: 7,
                encrypt_local_files: true,
            },
            
            auto_start: false,
            hardware_acceleration: true,
            developer_mode: false,
            analytics_enabled: true,
            
            server_url: "https://localhost:8443".to_string(),
            use_proxy: false,
            proxy_url: None,
            
            experimental_features: HashMap::from([
                ("voice_notes".to_string(), true),
                ("video_messages".to_string(), true),
                ("message_reactions".to_string(), true),
                ("pinned_messages".to_string(), true),
                ("chat_folders".to_string(), false),
            ]),
        }
    }
}

pub fn show_settings_panel(ui: &mut Ui, state: &mut crate::types::AppSettings) -> bool {
    let mut settings_changed = false;
    
    ScrollArea::vertical()
        .id_source("settings_scroll")
        .show(ui, |ui| {
            ui.heading("⚙️ Settings");
            ui.separator();
            
            settings_changed |= show_appearance_settings(ui, state);
            settings_changed |= show_notification_settings(ui, state);
            settings_changed |= show_privacy_settings(ui, state);
            settings_changed |= show_chat_settings(ui, state);
            settings_changed |= show_media_settings(ui, state);
            settings_changed |= show_call_settings(ui, state);
            settings_changed |= show_storage_settings(ui, state);
            settings_changed |= show_advanced_settings(ui, state);
        });
    
    settings_changed
}

fn show_appearance_settings(ui: &mut Ui, state: &mut SettingsState) -> bool {
    let mut changed = false;
    
    ui.heading("🎨 Appearance");
    
    Grid::new("appearance_grid")
        .num_columns(2)
        .spacing([20.0, 8.0])
        .show(ui, |ui| {
            // Theme
            ui.label("Theme");
            ComboBox::from_id_source("theme_combo")
                .selected_text(match state.theme {
                    Theme::Light => "Light",
                    Theme::Dark => "Dark",
                    Theme::System => "System",
                })
                .show_ui(ui, |ui| {
                    if ui.selectable_value(&mut state.theme, Theme::Light, "Light").clicked() {
                        changed = true;
                    }
                    if ui.selectable_value(&mut state.theme, Theme::Dark, "Dark").clicked() {
                        changed = true;
                    }
                    if ui.selectable_value(&mut state.theme, Theme::System, "System").clicked() {
                        changed = true;
                    }
                });
            ui.end_row();
            
            // Font size
            ui.label("Font Size");
            if ui.add(Slider::new(&mut state.font_size, 10.0..=22.0).suffix("px")).changed() {
                changed = true;
            }
            ui.end_row();
            
            // Message font
            ui.label("Message Font");
            ComboBox::from_id_source("message_font")
                .selected_text(format!("{:?}", state.chat.font))
                .show_ui(ui, |ui| {
                    for font in [MessageFont::System, MessageFont::Inter, MessageFont::Roboto, MessageFont::OpenSans, MessageFont::Monospace] {
                        if ui.selectable_value(&mut state.chat.font, font, format!("{:?}", font)).clicked() {
                            changed = true;
                        }
                    }
                });
            ui.end_row();
            
            // Message density
            ui.label("Message Density");
            ComboBox::from_id_source("message_density")
                .selected_text(match state.chat.density {
                    MessageDensity::Comfortable => "Comfortable",
                    MessageDensity::Compact => "Compact",
                    MessageDensity::Cozy => "Cozy",
                })
                .show_ui(ui, |ui| {
                    if ui.selectable_value(&mut state.chat.density, MessageDensity::Comfortable, "Comfortable").clicked() {
                        changed = true;
                    }
                    if ui.selectable_value(&mut state.chat.density, MessageDensity::Compact, "Compact").clicked() {
                        changed = true;
                    }
                    if ui.selectable_value(&mut state.chat.density, MessageDensity::Cozy, "Cozy").clicked() {
                        changed = true;
                    }
                });
            ui.end_row();
        });
    
    ui.separator();
    changed
}

fn show_notification_settings(ui: &mut Ui, state: &mut SettingsState) -> bool {
    let mut changed = false;
    
    ui.heading("🔔 Notifications");
    
    ui.checkbox(&mut state.notifications.enabled, "Enable notifications")
        .on_hover_text("Show notifications for new messages");
    
    if state.notifications.enabled {
        ui.indent("notifications_indent", |ui| {
            Grid::new("notifications_grid")
                .num_columns(2)
                .spacing([20.0, 8.0])
                .show(ui, |ui| {
                    ui.checkbox(&mut state.notifications.sound, "Sound");
                    if ui.checkbox(&mut state.notifications.vibration, "Vibration").changed() {
                        changed = true;
                    }
                    ui.end_row();
                    
                    ui.checkbox(&mut state.notifications.preview, "Show preview");
                    if ui.checkbox(&mut state.notifications.group_notifications, "Group notifications").changed() {
                        changed = true;
                    }
                    ui.end_row();
                    
                    ui.label("Priority");
                    ComboBox::from_id_source("notification_priority")
                        .selected_text(format!("{:?}", state.notifications.priority))
                        .show_ui(ui, |ui| {
                            for priority in [NotificationPriority::Low, NotificationPriority::Medium, NotificationPriority::High, NotificationPriority::Urgent] {
                                if ui.selectable_value(&mut state.notifications.priority, priority, format!("{:?}", priority)).clicked() {
                                    changed = true;
                                }
                            }
                        });
                    ui.end_row();
                });
        });
    }
    
    ui.separator();
    changed
}

fn show_privacy_settings(ui: &mut Ui, state: &mut SettingsState) -> bool {
    let mut changed = false;
    
    ui.heading("🛡️ Privacy & Security");
    
    Grid::new("privacy_grid")
        .num_columns(2)
        .spacing([20.0, 8.0])
        .show(ui, |ui| {
            ui.checkbox(&mut state.privacy.read_receipts, "Read receipts");
            if ui.checkbox(&mut state.privacy.typing_indicators, "Typing indicators").changed() {
                changed = true;
            }
            ui.end_row();
            
            ui.checkbox(&mut state.privacy.online_status, "Online status");
            if ui.checkbox(&mut state.privacy.last_seen, "Last seen").changed() {
                changed = true;
            }
            ui.end_row();
            
            ui.checkbox(&mut state.privacy.add_by_phone, "Add by phone number");
            if ui.checkbox(&mut state.privacy.block_unknown, "Block unknown contacts").changed() {
                changed = true;
            }
            ui.end_row();
            
            ui.checkbox(&mut state.privacy.encrypted_backups, "Encrypted backups");
            ui.end_row();
            
            ui.label("Profile photo");
            ComboBox::from_id_source("profile_photo_privacy")
                .selected_text(match state.privacy.profile_photo {
                    PrivacyLevel::Everyone => "Everyone",
                    PrivacyLevel::Contacts => "Contacts",
                    PrivacyLevel::Nobody => "Nobody",
                })
                .show_ui(ui, |ui| {
                    if ui.selectable_value(&mut state.privacy.profile_photo, PrivacyLevel::Everyone, "Everyone").clicked() {
                        changed = true;
                    }
                    if ui.selectable_value(&mut state.privacy.profile_photo, PrivacyLevel::Contacts, "Contacts").clicked() {
                        changed = true;
                    }
                    if ui.selectable_value(&mut state.privacy.profile_photo, PrivacyLevel::Nobody, "Nobody").clicked() {
                        changed = true;
                    }
                });
            ui.end_row();
        });
    
    ui.separator();
    changed
}

fn show_chat_settings(ui: &mut Ui, state: &mut SettingsState) -> bool {
    let mut changed = false;
    
    ui.heading("💬 Chat");
    
    Grid::new("chat_grid")
        .num_columns(2)
        .spacing([20.0, 8.0])
        .show(ui, |ui| {
            ui.checkbox(&mut state.chat.enter_sends, "Enter key sends message");
            if ui.checkbox(&mut state.chat.show_avatars, "Show avatars").changed() {
                changed = true;
            }
            ui.end_row();
            
            ui.checkbox(&mut state.chat.show_timestamps, "Show timestamps");
            if ui.checkbox(&mut state.chat.show_emojis, "Show emojis").changed() {
                changed = true;
            }
            ui.end_row();
            
            ui.checkbox(&mut state.chat.markdown_support, "Markdown support");
            if ui.checkbox(&mut state.chat.auto_play_gifs, "Auto-play GIFs").changed() {
                changed = true;
            }
            ui.end_row();
        });
    
    ui.separator();
    changed
}

fn show_media_settings(ui: &mut Ui, state: &mut SettingsState) -> bool {
    let mut changed = false;
    
    ui.heading("📷 Media");
    
    ui.label("Auto-download media");
    ComboBox::from_id_source("auto_download")
        .selected_text(match state.media.auto_download {
            AutoDownloadLevel::Never => "Never",
            AutoDownloadLevel::WiFIOnly => "Wi-Fi only",
            AutoDownloadLevel::PhotosOnly => "Photos only",
            AutoDownloadLevel::MediaOnly => "Media only",
            AutoDownloadLevel::All => "All media",
        })
        .show_ui(ui, |ui| {
            for level in [AutoDownloadLevel::Never, AutoDownloadLevel::WiFIOnly, AutoDownloadLevel::PhotosOnly, AutoDownloadLevel::MediaOnly, AutoDownloadLevel::All] {
                if ui.selectable_value(&mut state.media.auto_download, level, match level {
                    AutoDownloadLevel::Never => "Never",
                    AutoDownloadLevel::WiFIOnly => "Wi-Fi only",
                    AutoDownloadLevel::PhotosOnly => "Photos only",
                    AutoDownloadLevel::MediaOnly => "Media only",
                    AutoDownloadLevel::All => "All media",
                }).clicked() {
                    changed = true;
                }
            }
        });
    
    Grid::new("media_grid")
        .num_columns(2)
        .spacing([20.0, 8.0])
        .show(ui, |ui| {
            ui.label("Video quality");
            ComboBox::from_id_source("video_quality")
                .selected_text(match state.media.video_quality {
                    VideoQuality::Low => "480p",
                    VideoQuality::Medium => "720p",
                    VideoQuality::High => "1080p",
                    VideoQuality::HD => "1440p",
                })
                .show_ui(ui, |ui| {
                    if ui.selectable_value(&mut state.media.video_quality, VideoQuality::Low, "480p").clicked() {
                        changed = true;
                    }
                    if ui.selectable_value(&mut state.media.video_quality, VideoQuality::Medium, "720p").clicked() {
                        changed = true;
                    }
                    if ui.selectable_value(&mut state.media.video_quality, VideoQuality::High, "1080p").clicked() {
                        changed = true;
                    }
                    if ui.selectable_value(&mut state.media.video_quality, VideoQuality::HD, "1440p").clicked() {
                        changed = true;
                    }
                });
            ui.end_row();
            
            ui.label("Image quality");
            if ui.add(Slider::new(&mut state.media.image_quality, 10..=100).suffix("%")).changed() {
                changed = true;
            }
            ui.end_row();
            
            ui.checkbox(&mut state.media.save_to_gallery, "Save to gallery");
            if ui.checkbox(&mut state.media.use_less_data, "Use less data").changed() {
                changed = true;
            }
            ui.end_row();
            
            ui.checkbox(&mut state.media.stream_videos, "Stream videos");
            ui.end_row();
        });
    
    ui.separator();
    changed
}

fn show_call_settings(ui: &mut Ui, state: &mut SettingsState) -> bool {
    let mut changed = false;
    
    ui.heading("📞 Calls");
    
    Grid::new("call_grid")
        .num_columns(2)
        .spacing([20.0, 8.0])
        .show(ui, |ui| {
            ui.checkbox(&mut state.calls.noise_suppression, "Noise suppression");
            if ui.checkbox(&mut state.calls.echo_cancellation, "Echo cancellation").changed() {
                changed = true;
            }
            ui.end_row();
            
            ui.checkbox(&mut state.calls.auto_answer, "Auto-answer");
            if ui.checkbox(&mut state.calls.vibration_on_call, "Vibration on call").changed() {
                changed = true;
            }
            ui.end_row();
            
            ui.checkbox(&mut state.calls.low_data_usage, "Low data usage");
            ui.end_row();
            
            ui.label("Video bitrate");
            if ui.add(Slider::new(&mut state.calls.video_bitrate, 500..=10000).suffix(" kbps")).changed() {
                changed = true;
            }
            ui.end_row();
            
            ui.label("Audio bitrate");
            if ui.add(Slider::new(&mut state.calls.audio_bitrate, 64..=320).suffix(" kbps")).changed() {
                changed = true;
            }
            ui.end_row();
        });
    
    ui.separator();
    changed
}

fn show_storage_settings(ui: &mut Ui, state: &mut SettingsState) -> bool {
    let mut changed = false;
    
    ui.heading("💾 Storage");
    
    Grid::new("storage_grid")
        .num_columns(2)
        .spacing([20.0, 8.0])
        .show(ui, |ui| {
            ui.checkbox(&mut state.storage.auto_cleanup, "Auto-cleanup");
            if ui.checkbox(&mut state.storage.encrypt_local_files, "Encrypt local files").changed() {
                changed = true;
            }
            ui.end_row();
            
            if state.storage.auto_cleanup {
                ui.label("Cleanup after");
                if ui.add(Slider::new(&mut state.storage.cleanup_after_days, 1..=365).suffix(" days")).changed() {
                    changed = true;
                }
                ui.end_row();
            }
            
            ui.label("Max cache size");
            if ui.add(Slider::new(&mut state.storage.max_cache_size, 128..=8192).suffix(" MB")).changed() {
                changed = true;
            }
            ui.end_row();
            
            ui.label("Backup interval");
            if ui.add(Slider::new(&mut state.storage.backup_interval, 1..=30).suffix(" days")).changed() {
                changed = true;
            }
            ui.end_row();
        });
    
    // Storage usage info
    ui.add_space(10.0);
    ui.collapsing("Storage Usage", |ui| {
        // TODO: Implement actual storage usage calculation
        ui.label("Chat data: 245 MB");
        ui.label("Media cache: 567 MB");
        ui.label("Other: 23 MB");
        ui.label(RichText::new("Total: 835 MB").strong());
        
        ui.add_space(10.0);
        if ui.button("Clear Cache").clicked() {
            // TODO: Implement cache clearing
            changed = true;
        }
    });
    
    ui.separator();
    changed
}

fn show_advanced_settings(ui: &mut Ui, state: &mut SettingsState) -> bool {
    let mut changed = false;
    
    ui.heading("🔧 Advanced");
    
    Grid::new("advanced_grid")
        .num_columns(2)
        .spacing([20.0, 8.0])
        .show(ui, |ui| {
            ui.checkbox(&mut state.auto_start, "Start with system");
            if ui.checkbox(&mut state.hardware_acceleration, "Hardware acceleration").changed() {
                changed = true;
            }
            ui.end_row();
            
            ui.checkbox(&mut state.developer_mode, "Developer mode");
            if ui.checkbox(&mut state.analytics_enabled, "Analytics").changed() {
                changed = true;
            }
            ui.end_row();
            
            ui.label("Server URL");
            if ui.text_edit_singleline(&mut state.server_url).changed() {
                changed = true;
            }
            ui.end_row();
            
            ui.checkbox(&mut state.use_proxy, "Use proxy");
            if state.use_proxy {
                ui.label("Proxy URL");
                if ui.text_edit_singleline(state.proxy_url.get_or_insert_with(|| "".to_string())).changed() {
                    changed = true;
                }
                ui.end_row();
            }
        });
    
    // Experimental features
    ui.add_space(10.0);
    ui.collapsing("Experimental Features", |ui| {
        for (feature, enabled) in &mut state.experimental_features {
            if ui.checkbox(enabled, feature.replace('_', " ")).changed() {
                changed = true;
            }
        }
    });
    
    // Reset settings
    ui.add_space(20.0);
    ui.horizontal(|ui| {
        if ui.button("Reset to Defaults").clicked() {
            *state = SettingsState::default();
            changed = true;
        }
        
        if ui.button("Export Settings").clicked() {
            // TODO: Implement settings export
        }
        
        if ui.button("Import Settings").clicked() {
            // TODO: Implement settings import
        }
    });
    
    changed
}

// Helper functions for settings management
impl SettingsState {
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
    
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let json = std::fs::read_to_string(path)?;
        let settings = serde_json::from_str(&json)?;
        Ok(settings)
    }
    
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        
        if self.server_url.is_empty() {
            errors.push("Server URL cannot be empty".to_string());
        }
        
        if self.font_size < 10.0 || self.font_size > 22.0 {
            errors.push("Font size must be between 10 and 22".to_string());
        }
        
        if self.storage.max_cache_size < 128 {
            errors.push("Maximum cache size must be at least 128MB".to_string());
        }
        
        errors
    }
    
    pub fn get_effective_theme(&self) -> Theme {
        match self.theme {
            Theme::System => {
                // TODO: Detect system theme
                Theme::Dark
            }
            theme => theme,
        }
    }
}
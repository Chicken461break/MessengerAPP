pub mod auth;
pub mod main;
pub mod chat;
pub mod sidebar;
pub mod settings;
pub mod components;

// Color palette for modern minimalist design
pub struct Colors;

impl Colors {
    // Primary colors
    pub const PRIMARY: egui::Color32 = egui::Color32::from_rgb(59, 130, 246); // Blue-500
    pub const PRIMARY_HOVER: egui::Color32 = egui::Color32::from_rgb(37, 99, 235); // Blue-600
    pub const PRIMARY_LIGHT: egui::Color32 = egui::Color32::from_rgb(147, 197, 253); // Blue-300
    
    // Semantic colors
    pub const SUCCESS: egui::Color32 = egui::Color32::from_rgb(34, 197, 94); // Green-500
    pub const WARNING: egui::Color32 = egui::Color32::from_rgb(251, 191, 36); // Amber-400
    pub const ERROR: egui::Color32 = egui::Color32::from_rgb(239, 68, 68); // Red-500
    pub const INFO: egui::Color32 = egui::Color32::from_rgb(99, 102, 241); // Indigo-500
    
    // Text colors
    pub const TEXT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(17, 24, 39); // Gray-900
    pub const TEXT_SECONDARY: egui::Color32 = egui::Color32::from_rgb(107, 114, 128); // Gray-500
    pub const TEXT_MUTED: egui::Color32 = egui::Color32::from_rgb(156, 163, 175); // Gray-400
    
    // Background colors (dark mode)
    pub const BG_DARK: egui::Color32 = egui::Color32::from_rgb(17, 24, 39); // Gray-900
    pub const BG_DARK_ELEVATED: egui::Color32 = egui::Color32::from_rgb(31, 41, 55); // Gray-800
    pub const BG_DARK_SURFACE: egui::Color32 = egui::Color32::from_rgb(55, 65, 81); // Gray-700
    
    // Online status
    pub const ONLINE: egui::Color32 = egui::Color32::from_rgb(34, 197, 94); // Green-500
    pub const OFFLINE: egui::Color32 = egui::Color32::from_rgb(156, 163, 175); // Gray-400
}

pub fn format_timestamp(timestamp: &chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let duration = now.signed_duration_since(*timestamp);
    
    if duration.num_seconds() < 60 {
        "Just now".to_string()
    } else if duration.num_minutes() < 60 {
        format!("{}m ago", duration.num_minutes())
    } else if duration.num_hours() < 24 {
        format!("{}h ago", duration.num_hours())
    } else if duration.num_days() < 7 {
        format!("{}d ago", duration.num_days())
    } else {
        timestamp.format("%b %d, %Y").to_string()
    }
}

pub fn format_file_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
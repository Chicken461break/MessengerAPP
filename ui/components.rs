// src/ui/components.rs
use eframe::egui::*;

// Remove the problematic imports and simplify
pub use eframe::egui::{Ui, Response, Color32, RichText, Sense, Align2};

/// Component theme configuration
#[derive(Clone, Debug)]
pub struct Theme {
    pub primary_color: Color32,
    pub secondary_color: Color32,
    pub success_color: Color32,
    pub warning_color: Color32,
    pub error_color: Color32,
    pub background_color: Color32,
    pub surface_color: Color32,
    pub text_primary: Color32,
    pub text_secondary: Color32,
    pub border_color: Color32,
    pub corner_radius: f32,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            primary_color: Color32::from_rgb(59, 130, 246),
            secondary_color: Color32::from_rgb(107, 114, 128),
            success_color: Color32::from_rgb(16, 185, 129),
            warning_color: Color32::from_rgb(245, 158, 11),
            error_color: Color32::from_rgb(239, 68, 68),
            background_color: Color32::from_rgb(249, 250, 251),
            surface_color: Color32::from_rgb(255, 255, 255),
            text_primary: Color32::from_rgb(17, 24, 39),
            text_secondary: Color32::from_rgb(107, 114, 128),
            border_color: Color32::from_rgb(229, 231, 235),
            corner_radius: 8.0,
        }
    }
}

/// Avatar configuration
#[derive(Clone, Debug)]
pub struct AvatarConfig {
    pub size: f32,
    pub show_border: bool,
    pub border_color: Color32,
    pub border_width: f32,
    pub text_color: Color32,
    pub font_scale: f32,
}

impl Default for AvatarConfig {
    fn default() -> Self {
        Self {
            size: 32.0,
            show_border: false,
            border_color: Color32::TRANSPARENT,
            border_width: 2.0,
            text_color: Color32::WHITE,
            font_scale: 0.5,
        }
    }
}

/// Production-ready avatar component
pub struct Avatar<'a> {
    display_name: &'a str,
    avatar_url: Option<&'a str>,
    config: AvatarConfig,
    on_click: Option<Box<dyn FnOnce() + 'a>>,
}

impl<'a> Avatar<'a> {
    pub fn new(display_name: &'a str) -> Self {
        Self {
            display_name,
            avatar_url: None,
            config: AvatarConfig::default(),
            on_click: None,
        }
    }

    pub fn with_url(mut self, url: &'a str) -> Self {
        self.avatar_url = Some(url);
        self
    }

    pub fn with_config(mut self, config: AvatarConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_on_click<F: FnOnce() + 'a>(mut self, callback: F) -> Self {
        self.on_click = Some(Box::new(callback));
        self
    }

    pub fn show(self, ui: &mut Ui) -> Response {
        let size = Vec2::splat(self.config.size);
        let (rect, response) = ui.allocate_exact_size(size, Sense::click());
        
        if response.clicked() {
            if let Some(callback) = self.on_click {
                callback();
            }
        }

        let painter = ui.painter();
        let center = rect.center();
        let radius = self.config.size / 2.0;

        // Draw avatar background
        let bg_color = color_for_name(self.display_name);

        painter.circle_filled(center, radius, bg_color);
        if self.config.show_border {
            painter.circle_stroke(center, radius, Stroke::new(self.config.border_width, self.config.border_color));
        }

        // Draw initials
        draw_initial_fallback(&painter, center, self.display_name, &self.config);

        response
    }
}

fn draw_initial_fallback(painter: &Painter, center: Pos2, display_name: &str, config: &AvatarConfig) {
    let initials = initials(display_name);
    let font_size = config.size * config.font_scale;
    
    painter.text(
        center,
        Align2::CENTER_CENTER,
        initials,
        FontId::proportional(font_size),
        config.text_color,
    );
}

/// Message bubble component
pub struct MessageBubble<'a> {
    content: &'a str,
    sender: &'a str,
    avatar_url: Option<&'a str>,
    timestamp: Option<&'a str>,
    is_user: bool,
    theme: &'a Theme,
}

impl<'a> MessageBubble<'a> {
    pub fn new(content: &'a str, sender: &'a str, theme: &'a Theme) -> Self {
        Self {
            content,
            sender,
            avatar_url: None,
            timestamp: None,
            is_user: false,
            theme,
        }
    }

    pub fn from_user(mut self) -> Self {
        self.is_user = true;
        self
    }

    pub fn with_avatar_url(mut self, url: &'a str) -> Self {
        self.avatar_url = Some(url);
        self
    }

    pub fn with_timestamp(mut self, timestamp: &'a str) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn show(self, ui: &mut Ui) -> Response {
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                if !self.is_user {
                    ui.vertical(|ui| {
                        ui.add_space(4.0);
                        Avatar::new(self.sender)
                            .with_url(self.avatar_url.unwrap_or(""))
                            .with_config(AvatarConfig {
                                size: 28.0,
                                ..Default::default()
                            })
                            .show(ui);
                    });
                }

                ui.vertical(|ui| {
                    if !self.is_user {
                        ui.label(RichText::new(self.sender).color(self.theme.text_secondary).size(12.0));
                    }

                    // Message content
                    let bubble_color = if self.is_user {
                        self.theme.primary_color
                    } else {
                        self.theme.surface_color
                    };
                    
                    let text_color = if self.is_user {
                        Color32::WHITE
                    } else {
                        self.theme.text_primary
                    };

                    let response = Frame::default()
                        .fill(bubble_color)
                        .rounding(12.0)
                        .inner_margin(Margin::symmetric(12.0, 8.0))
                        .show(ui, |ui| {
                            ui.label(RichText::new(self.content).color(text_color));
                        })
                        .response;

                    if let Some(timestamp) = self.timestamp {
                        ui.label(RichText::new(timestamp).color(text_color.gamma_multiply(0.7)).size(10.0));
                    }

                    response
                });

                if self.is_user {
                    ui.vertical(|ui| {
                        ui.add_space(4.0);
                        Avatar::new(self.sender)
                            .with_url(self.avatar_url.unwrap_or(""))
                            .with_config(AvatarConfig {
                                size: 28.0,
                                ..Default::default()
                            })
                            .show(ui);
                    });
                }
            })
        }).response
    }
}

/// Styled button component
pub struct AppButton<'a> {
    label: &'a str,
    enabled: bool,
    on_click: Option<Box<dyn FnOnce() + 'a>>,
}

impl<'a> AppButton<'a> {
    pub fn new(label: &'a str) -> Self {
        Self {
            label,
            enabled: true,
            on_click: None,
        }
    }

    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn with_on_click<F: FnOnce() + 'a>(mut self, callback: F) -> Self {
        self.on_click = Some(Box::new(callback));
        self
    }

    pub fn show(self, ui: &mut Ui, theme: &Theme) -> Response {
        let button = Button::new(RichText::new(self.label).size(14.0))
            .fill(theme.primary_color)
            .min_size(Vec2::new(80.0, 32.0));

        let response = ui.add_enabled(self.enabled, button);

        if response.clicked() {
            if let Some(callback) = self.on_click {
                callback();
            }
        }

        response
    }
}

/// Utility functions
fn initials(name: &str) -> String {
    name
        .split_whitespace()
        .take(2)
        .filter_map(|w| w.chars().next())
        .collect::<String>()
        .to_uppercase()
}

fn color_for_name(name: &str) -> Color32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    let hash = hasher.finish();
    
    const COLORS: [Color32; 8] = [
        Color32::from_rgb(37, 99, 235),   // blue
        Color32::from_rgb(16, 185, 129),  // green
        Color32::from_rgb(244, 63, 94),   // red
        Color32::from_rgb(251, 191, 36),  // yellow
        Color32::from_rgb(168, 85, 247),  // purple
        Color32::from_rgb(251, 113, 133), // pink
        Color32::from_rgb(52, 211, 153),  // emerald
        Color32::from_rgb(59, 130, 246),  // light blue
    ];
    COLORS[(hash % COLORS.len() as u64) as usize]
}

/// Quick helper functions
pub fn quick_avatar(ui: &mut Ui, display_name: &str, avatar_url: Option<&str>) -> Response {
    Avatar::new(display_name)
        .with_url(avatar_url.unwrap_or(""))
        .show(ui)
}

pub fn quick_button(ui: &mut Ui, label: &str, theme: &Theme) -> Response {
    AppButton::new(label).show(ui, theme)
}
use egui::*;
use crate::{
    MessengerApp, Chat, Message, MessageType, CallType, ActiveCall, 
    FileTransfer, AppEvent
};
use crate::ui::components::{self, MessageBubble, Avatar, AvatarConfig, Theme, AppButton};

/// Shows the main chat view for a specific chat
pub fn show_chat_view(app: &mut MessengerApp, ui: &mut Ui, chat_id: &str) {
    // Pre-extract data to avoid multiple mutable borrows in closures
    let chat_opt = app.chats.get(chat_id).cloned();
    let active_call = app.active_call.clone();
    let messages_vec = app.messages.get(chat_id).cloned().unwrap_or_default();
    let typing_indicators = app.typing_indicators.clone();

    if let Some(chat) = chat_opt {
        ui.vertical(|ui| {
            show_chat_header(app, ui, &chat);
            ui.separator();

            if let Some(ac) = &active_call {
                if ac.chat_id == chat_id {
                    show_active_call_banner(app, ui, ac);
                    ui.separator();
                }
            }
            show_messages_area(app, ui, &chat, &messages_vec);
            ui.separator();

            show_typing_indicators(ui, &typing_indicators, chat_id);
            show_message_input(app, ui, chat_id);
        });
    } else {
        show_chat_not_found(ui, chat_id);
    }
}

fn show_chat_header(app: &mut MessengerApp, ui: &mut Ui, chat: &Chat) {
    let contacts = app.contacts.clone();
    let selected_chat_id = chat.id.clone();
    ui.horizontal(|ui| {
        if ui.add(Button::new("← Back").small()).clicked() {
            app.current_view = crate::types::AppView::ChatList;
            app.selected_chat_id = None;
        }

        ui.horizontal(|ui| {
            let icon = match chat.r#type {
                crate::types::ChatType::Private => "👤",
                crate::types::ChatType::Group => "👥",
            };
            ui.label(RichText::new(icon).size(20.0));
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(&chat.title)
                        .size(16.0)
                        .color(ui.style().visuals.strong_text_color()),
                );
                match chat.r#type {
                    crate::types::ChatType::Private => {
                        if let Some(participant) = chat.participant_ids.first() {
                            if let Some(contact) = contacts.iter().find(|c| c.id == *participant) {
                                let status_text = if contact.is_online {
                                    "Online".to_owned()
                                } else {
                                    format!("Last seen {}", crate::ui::format_timestamp(&contact.last_seen))
                                };
                                ui.label(
                                    RichText::new(status_text)
                                        .size(12.0)
                                        .color(ui.style().visuals.weak_text_color()),
                                );
                            }
                        }
                    }
                    crate::types::ChatType::Group => {
                        let online_count = chat.participant_ids.iter()
                            .filter(|id| contacts.iter().any(|c| &c.id == *id && c.is_online))
                            .count();
                        ui.label(
                            RichText::new(format!(
                                "{} members, {} online",
                                chat.participant_ids.len(),
                                online_count
                            ))
                            .size(12.0)
                            .color(ui.style().visuals.weak_text_color()),
                        );
                    }
                }
            });
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if app.active_call.is_none() {
                if ui.button("📞").on_hover_text("Voice call").clicked() {
                    start_voice_call(app, &selected_chat_id);
                }
                if ui.button("🎥").on_hover_text("Video call").clicked() {
                    start_video_call(app, &selected_chat_id);
                }
            }
            if ui.button("ℹ️").on_hover_text("Chat info").clicked() {
                show_chat_info_modal(app, chat);
            }
            if ui.button("⋯").on_hover_text("More actions").clicked() {
                // TODO: show context menu
            }
        });
    });
}

fn show_active_call_banner(app: &mut MessengerApp, ui: &mut Ui, active_call: &ActiveCall) {
    Frame::default()
        .fill(Color32::from_rgba_premultiplied(59, 130, 246, 30))
        .inner_margin(Margin::symmetric(12.0, 8.0))
        .rounding(8.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let call_icon = match active_call.call_type {
                    CallType::Voice => "📞",
                    CallType::Video => "🎥",
                };
                ui.label(RichText::new(call_icon).size(16.0));
                ui.vertical(|ui| {
                    ui.label(RichText::new("Active Call").size(14.0));
                    ui.label(
                        RichText::new(format!(
                            "{} participants connected",
                            active_call.participants.values().filter(|&&v| v).count()
                        ))
                        .size(12.0)
                        .color(ui.style().visuals.weak_text_color()),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Leave").clicked() {
                        end_call(app, &active_call.call_id);
                    }
                    if ui.button("Join").clicked() {
                        join_call(app, &active_call.call_id);
                    }
                });
            });
        });
}

fn show_messages_area(app: &mut MessengerApp, ui: &mut Ui, chat: &Chat, messages: &[Message]) {
    let available_height = ui.available_height() - 150.0;
    Frame::default()
        .fill(ui.style().visuals.faint_bg_color)
        .inner_margin(Margin::symmetric(8.0, 4.0))
        .show(ui, |ui| {
            ScrollArea::vertical()
                .id_source(format!("chat_messages_{}", chat.id))
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .max_height(available_height)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if messages.is_empty() {
                        show_empty_chat_state(ui, chat);
                    } else {
                        show_messages_list(app, ui, chat, messages);
                    }
                });
        });
}

fn show_typing_indicators(ui: &mut Ui, typing_indicators: &std::collections::HashMap<String, crate::TypingIndicator>, chat_id: &str) {
    let typing_users: Vec<_> = typing_indicators.values()
        .filter(|indicator| indicator.chat_id == chat_id && indicator.is_typing)
        .collect();
    if !typing_users.is_empty() {
        let names: Vec<_> = typing_users.iter()
            .map(|indicator| indicator.user_name.clone())
            .collect();
        let text = if names.len() == 1 {
            format!("{} is typing...", names[0])
        } else if names.len() == 2 {
            format!("{} and {} are typing...", names[0], names[1])
        } else {
            format!("{} people are typing...", names.len())
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new("✏️").size(12.0).color(ui.style().visuals.weak_text_color()));
            ui.label(RichText::new(text).size(12.0).color(ui.style().visuals.weak_text_color()));
        });
    }
}

fn show_empty_chat_state(ui: &mut Ui, chat: &Chat) {
    ui.vertical_centered(|ui| {
        ui.add_space(40.0);
        ui.label(
            RichText::new("💬")
                .size(48.0)
                .color(ui.style().visuals.weak_text_color()),
        );
        ui.add_space(16.0);
        ui.label(
            RichText::new("No messages yet")
                .size(16.0)
                .color(ui.style().visuals.strong_text_color()),
        );
        ui.label(
            RichText::new(format!("Send a message to start the conversation with {}", chat.title))
                .size(14.0)
                .color(ui.style().visuals.weak_text_color()),
        );
        ui.add_space(20.0);
        ui.horizontal(|ui| {
            if ui.button("👋 Say Hello!").clicked() {
                // Could trigger hello
            }
            if ui.button("📷 Send Photo").clicked() {
                // Could trigger file picker
            }
        });
    });
}

fn show_messages_list(app: &mut MessengerApp, ui: &mut Ui, chat: &Chat, messages: &[Message]) {
    let theme = components::Theme::default();
    ui.vertical(|ui| {
        if let Some(first_message) = messages.first() {
            show_date_separator(ui, &first_message.timestamp);
        }
        let mut last_date = None;
        for (index, message) in messages.iter().enumerate() {
            let current_date = message.timestamp.date_naive();
            if last_date.map(|d| d != current_date).unwrap_or(true) {
                if index > 0 {
                    show_date_separator(ui, &message.timestamp);
                }
                last_date = Some(current_date);
            }
            show_message(app, ui, message, chat, &theme);
            if index < messages.len() - 1 {
                let next_message = &messages[index + 1];
                if message.sender_id != next_message.sender_id {
                    ui.add_space(8.0);
                } else {
                    ui.add_space(2.0);
                }
            }
        }
        ui.add_space(4.0);
    });
}

fn show_message(app: &mut MessengerApp, ui: &mut Ui, message: &Message, chat: &Chat, theme: &Theme) {
    let is_current_user = app.current_user.as_ref().map(|u| u.id == message.sender_id).unwrap_or(false);
    let sender_name = if is_current_user {
        "You".to_string()
    } else if let Some(contact) = app.contacts.iter().find(|c| c.id == message.sender_id) {
        contact.display_name.clone()
    } else {
        message.sender_id.clone()
    };
    let sender_avatar = if is_current_user {
        app.current_user.as_ref().and_then(|u| u.avatar_url.as_deref())
    } else {
        app.contacts.iter().find(|c| c.id == message.sender_id).and_then(|c| c.avatar_url.as_deref())
    };
    match &message.r#type {
        MessageType::Text => {
            if let Some(content) = &message.content {
                MessageBubble::new(content, &sender_name, theme)
                    .from_user()
                    .with_avatar_url(sender_avatar.unwrap_or(""))
                    .with_timestamp(&format_timestamp(&message.timestamp))
                    .show(ui);
            }
        }
        MessageType::Image => {
            if let Some(media_url) = &message.media_url {
                show_image_message(ui, message, media_url, &sender_name, is_current_user, theme);
            }
        }
        _ => {
            if let Some(content) = &message.content {
                MessageBubble::new(content, &sender_name, theme)
                    .from_user()
                    .show(ui);
            }
        }
    }
    if is_current_user {
        show_message_status(ui, message);
    }
}

fn show_image_message(
    ui: &mut Ui,
    message: &Message,
    media_url: &str,
    sender_name: &str,
    is_current_user: bool,
    theme: &components::Theme,
) {
    ui.vertical(|ui| {
        Frame::default()
            .fill(theme.surface_color)
            .stroke(Stroke::new(1.0, theme.border_color))
            .rounding(8.0)
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.label(RichText::new("🖼️").size(32.0));
                    ui.label("Image Message");
                    ui.horizontal(|ui| {
                        if ui.small_button("📥 Download").clicked() {
                            download_media(media_url, "image");
                        }
                        if ui.small_button("👁️ View").clicked() {
                            show_image_viewer(media_url);
                        }
                    });
                    ui.add_space(20.0);
                });
            });
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(sender_name)
                    .size(10.0)
                    .color(theme.text_secondary),
            );
            ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                ui.label(
                    RichText::new(format_timestamp(&message.timestamp))
                        .size(10.0)
                        .color(theme.text_secondary),
                );
            });
        });
    });
}

fn show_message_input(app: &mut MessengerApp, ui: &mut Ui, chat_id: &str) {
    let draft = app.message_input.entry(chat_id.to_string()).or_default();
    ui.vertical(|ui| {
        ui.horizontal(|ui| {
            if ui.small_button("📎").on_hover_text("Attach file").clicked() {
                show_file_picker(app, chat_id);
            }
            if ui.small_button("🖼️").on_hover_text("Send image").clicked() {
                show_image_picker(app, chat_id);
            }
        });
        ui.horizontal(|ui| {
            let _response = ui.add(
                TextEdit::multiline(draft)
                    .hint_text("Type a message...")
                    .desired_width(ui.available_width() - 80.0)
                    .desired_rows(1)
                    .id_source(format!("message_input_{}", chat_id)),
            );
            let send_enabled = !draft.trim().is_empty();
            if ui.add_enabled(send_enabled, Button::new("➤")).clicked() {
                send_message(app, chat_id, draft);
            }
        });
        if !draft.is_empty() {
            send_typing_indicator(app, chat_id, true);
        }
    });
}

fn show_chat_not_found(ui: &mut Ui, chat_id: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(100.0);
        ui.label(
            RichText::new("❌")
                .size(48.0)
                .color(Color32::from_rgb(239, 68, 68)),
        );
        ui.add_space(20.0);
        ui.label(
            RichText::new("Chat not found")
                .size(16.0)
                .color(ui.style().visuals.strong_text_color()),
        );
        ui.label(
            RichText::new(format!("Chat with ID '{}' could not be found", chat_id))
                .size(14.0)
                .color(ui.style().visuals.weak_text_color()),
        );
    });
}

fn show_date_separator(ui: &mut Ui, timestamp: &chrono::DateTime<chrono::Utc>) {
    ui.vertical_centered(|ui| {
        ui.separator();
        ui.label(
            RichText::new(timestamp.format("%B %d, %Y").to_string())
                .size(10.0)
                .color(ui.style().visuals.weak_text_color()),
        );
    });
}

fn show_message_status(ui: &mut Ui, message: &Message) {
    ui.horizontal(|ui| {
        ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
            ui.label(
                RichText::new("✓✓")
                    .size(10.0)
                    .color(ui.style().visuals.weak_text_color()),
            );
            if message.edited {
                ui.label(
                    RichText::new("(edited)")
                        .size(10.0)
                        .color(ui.style().visuals.weak_text_color()),
                );
            }
        });
    });
}

fn start_voice_call(app: &mut MessengerApp, chat_id: &str) {
    let network = app.network.clone();
    let chat_id = chat_id.to_string();
    app.runtime.spawn(async move {
        let sdp_offer = serde_json::json!({
            "type": "offer",
            "sdp": "voice-sdp-offer-placeholder"
        });
        let _ = network.send_call_offer(&chat_id, CallType::Voice, sdp_offer).await;
    });
}

fn start_video_call(app: &mut MessengerApp, chat_id: &str) {
    let network = app.network.clone();
    let chat_id = chat_id.to_string();
    app.runtime.spawn(async move {
        let sdp_offer = serde_json::json!({
            "type": "offer",
            "sdp": "video-sdp-offer-placeholder"
        });
        let _ = network.send_call_offer(&chat_id, CallType::Video, sdp_offer).await;
    });
}

fn end_call(app: &mut MessengerApp, _call_id: &str) {
    app.active_call = None;
}

fn join_call(_app: &mut MessengerApp, _call_id: &str) {
    // join logic here
}

fn show_chat_info_modal(app: &mut MessengerApp, chat: &Chat) {
    app.show_notification(
        "Chat Info".to_string(),
        format!("Information for {}", chat.title),
        crate::types::NotificationType::Info,
        None,
    );
}

fn download_media(_media_url: &str, _media_type: &str) {/* download */}
fn show_image_viewer(_media_url: &str) {}
fn extract_filename_from_url(url: &str) -> String {
    url.split('/').last().unwrap_or("file").to_string()
}
fn find_file_transfer(_media_url: &str) -> Option<FileTransfer> { None }
fn download_file(_media_url: &str, _filename: &str) {}
fn play_voice_message(_message: &Message) {}
fn play_video_message(_media_url: &str) {}
fn show_file_picker(app: &mut MessengerApp, chat_id: &str) {
    app.show_notification(
        "File Picker".to_string(),
        "File picker would open here".to_string(),
        crate::types::NotificationType::Info,
        None,
    );
}
fn show_image_picker(app: &mut MessengerApp, chat_id: &str) {
    app.show_notification(
        "Image Picker".to_string(),
        "Image picker would open here".to_string(),
        crate::types::NotificationType::Info,
        None,
    );
}
fn start_voice_recording(app: &mut MessengerApp, _chat_id: &str) {
    app.show_notification(
        "Voice Recording".to_string(),
        "Voice recording would start here".to_string(),
        crate::types::NotificationType::Info,
        None,
    );
}
fn send_message(app: &mut MessengerApp, chat_id: &str, draft: &mut String) {
    let content = draft.trim();
    if !content.is_empty() {
        let message_content = content.to_string();
        draft.clear();
        let network = app.network.clone();
        let chat_id = chat_id.to_string();
        app.runtime.spawn(async move {
            let _ = network.send_message(&chat_id, &message_content, MessageType::Text).await;
        });
        send_typing_indicator(app, chat_id, false);
    }
}
fn send_typing_indicator(app: &mut MessengerApp, chat_id: &str, is_typing: bool) {
    let network = app.network.clone();
    let chat_id = chat_id.to_string();
    app.runtime.spawn(async move {
        let _ = network.send_typing_indicator(&chat_id, is_typing).await;
    });
}
fn format_timestamp(timestamp: &chrono::DateTime<chrono::Utc>) -> String {
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
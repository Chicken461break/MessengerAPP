use egui::{Ui, ScrollArea, Button, Frame, Margin, RichText, Color32, Sense, Response};
use crate::{MessengerApp, Chat, ChatType};

/// Render the sidebar with a list of chats/groups
pub fn show_sidebar(app: &mut MessengerApp, ui: &mut Ui) {
    ui.vertical(|ui| {
        // Header with user info
        show_user_header(app, ui);
        
        ui.separator();
        ui.add_space(8.0);
        
        // Navigation buttons
        show_navigation_buttons(app, ui);
        
        ui.separator();
        ui.add_space(8.0);
        
        // Search bar
        show_search_bar(app, ui);
        
        ui.separator();
        ui.add_space(8.0);
        
        // Chats list
        show_chats_list(app, ui);
    });
}

/// Show user header with profile and status
fn show_user_header(app: &mut MessengerApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        if let Some(user) = &app.current_user {
            // User avatar/icon
            ui.vertical_centered(|ui| {
                let avatar_response = ui.add(
                    egui::Button::new(
                        RichText::new("👤").size(24.0)
                    )
                    .frame(false)
                    .min_size(egui::vec2(40.0, 40.0)),
                );
                
                if avatar_response.clicked() {
                    app.show_profile = true;
                }
                
                // Online status indicator
                let status_color = if user.is_online {
                    Color32::from_rgb(34, 197, 94) // Green
                } else {
                    Color32::from_rgb(156, 163, 175) // Gray
                };
                
                ui.painter().circle_filled(
                    avatar_response.rect.right_top() + egui::vec2(-4.0, 4.0),
                    4.0,
                    status_color,
                );
            });
            
            // User info
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(&user.display_name)
                        .size(14.0)
                        .color(ui.style().visuals.strong_text_color()),
                );
                
                ui.label(
                    RichText::new(&user.status)
                        .size(12.0)
                        .color(ui.style().visuals.weak_text_color()),
                );
            });
            
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("⚙️").clicked() {
                    app.show_settings = true;
                }
            });
        } else {
            ui.label("Not logged in");
        }
    });
}

/// Show navigation buttons for different views
fn show_navigation_buttons(app: &mut MessengerApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        let chat_list_active = matches!(app.current_view, crate::types::AppView::ChatList);
        let contacts_active = matches!(app.current_view, crate::types::AppView::Contacts);
        
        if ui.selectable_label(chat_list_active, "💬 Chats").clicked() {
            app.current_view = crate::types::AppView::ChatList;
        }
        
        if ui.selectable_label(contacts_active, "👥 Contacts").clicked() {
            app.current_view = crate::types::AppView::Contacts;
        }
    });
    
    ui.add_space(4.0);
    
    // New chat button
    if ui.button("💬 New Chat").clicked() {
        app.show_create_group = true;
    }
}

/// Show search bar for filtering chats
fn show_search_bar(app: &mut MessengerApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut app.search_query)
                .hint_text("🔍 Search chats...")
                .desired_width(ui.available_width() - 30.0),
        );
        
        if !app.search_query.is_empty() {
            if ui.button("✕").clicked() {
                app.search_query.clear();
            }
        }
    });
}

/// Show the list of chats
fn show_chats_list(app: &mut MessengerApp, ui: &mut Ui) {
    ui.push_id("chats_list", |ui| {
        if app.chats.is_empty() {
            show_empty_chats_state(app, ui);
        } else {
            show_chats_scroll_list(app, ui);
        }
    });
}

/// Show empty state when no chats are available
fn show_empty_chats_state(app: &mut MessengerApp, ui: &mut Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(40.0);
        
        ui.label(
            RichText::new("💬")
                .size(48.0)
                .color(ui.style().visuals.weak_text_color()),
        );
        
        ui.add_space(16.0);
        
        ui.label(
            RichText::new("No conversations yet")
                .size(14.0)
                .color(ui.style().visuals.strong_text_color()),
        );
        
        ui.label(
            RichText::new("Start a new chat to begin messaging")
                .size(12.0)
                .color(ui.style().visuals.weak_text_color()),
        );
        
        ui.add_space(16.0);
        
        if ui.button("Start Your First Chat").clicked() {
            app.show_create_group = true;
        }
    });
}

/// Show scrollable list of chats
fn show_chats_scroll_list(app: &mut MessengerApp, ui: &mut Ui) {
    ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            let mut filtered_chats: Vec<&Chat> = app.chats.values().collect();
            
            // Filter chats based on search query
            if !app.search_query.is_empty() {
                let query = app.search_query.to_lowercase();
                filtered_chats.retain(|chat| {
                    chat.title.to_lowercase().contains(&query) ||
                    chat.description.as_ref().map_or(false, |desc| desc.to_lowercase().contains(&query))
                });
            }
            
            // Sort chats by last activity (most recent first)
            filtered_chats.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));
            
            if filtered_chats.is_empty() && !app.search_query.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.label("No chats found matching your search");
                    if ui.button("Clear Search").clicked() {
                        app.search_query.clear();
                    }
                });
            } else {
                for chat in filtered_chats {
                    show_chat_list_item(app, ui, chat);
                }
            }
        });
}

/// Show individual chat list item
pub fn show_chat_list_item(app: &mut MessengerApp, ui: &mut Ui, chat: &Chat) {
    let is_selected = app.selected_chat_id.as_ref() == Some(&chat.id);
    let has_unread = chat.unread_count.unwrap_or(0) > 0;
    
    let response = Frame::default()
        .inner_margin(Margin::symmetric(8.0, 6.0))
        .fill(if is_selected {
            ui.style().visuals.selection.bg_fill
        } else {
            ui.style().visuals.faint_bg_color
        })
        .rounding(8.0)
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                // Chat icon based on type
                let icon = match chat.r#type {
                    ChatType::Private => "👤",
                    ChatType::Group => "👥",
                };
                
                ui.label(
                    RichText::new(icon)
                        .size(16.0)
                        .color(ui.style().visuals.weak_text_color()),
                );
                
                // Chat info
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(&chat.title)
                                .size(14.0)
                                .color(if has_unread {
                                    ui.style().visuals.strong_text_color()
                                } else {
                                    ui.style().visuals.text_color()
                                }),
                        );
                        
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if has_unread {
                                ui.label(
                                    RichText::new(chat.unread_count.unwrap_or(0).to_string())
                                        .size(12.0)
                                        .color(Color32::WHITE)
                                        .background_color(Color32::from_rgb(239, 68, 68)), // Red
                                );
                            }
                        });
                    });
                    
                    // Last message preview
                    if let Some(last_message) = &chat.last_message {
                        ui.label(
                            RichText::new(truncate_text(last_message, 30))
                                .size(12.0)
                                .color(ui.style().visuals.weak_text_color()),
                        );
                    }
                    
                    // Last activity time
                    ui.label(
                        RichText::new(format_timestamp(&chat.last_activity))
                            .size(10.0)
                            .color(ui.style().visuals.weak_text_color()),
                    );
                });
            });
        })
        .response;
    
    // Handle click
    if response.clicked() {
        app.selected_chat_id = Some(chat.id.clone());
        app.current_view = crate::types::AppView::Chat;
        
        // Mark as read if this chat was selected
        if let Some(selected_chat) = app.chats.get_mut(&chat.id) {
            if selected_chat.unread_count.unwrap_or(0) > 0 {
                selected_chat.unread_count = Some(0);
            }
        }
    }
    
    // Context menu on right-click
    response.context_menu(|ui| {
        if ui.button("📋 Copy Chat ID").clicked() {
            ui.output_mut(|o| o.copied_text = chat.id.clone());
            ui.close_menu();
        }
        
        if ui.button("🚪 Leave Chat").clicked() {
            // TODO: Implement leave chat functionality
            ui.close_menu();
        }
        
        ui.separator();
        
        if ui.button("📁 Archive Chat").clicked() {
            // TODO: Implement archive functionality
            ui.close_menu();
        }
    });
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Truncate text with ellipsis
fn truncate_text(text: &str, max_length: usize) -> String {
    if text.len() <= max_length {
        text.to_string()
    } else {
        format!("{}...", &text[..max_length - 3])
    }
}

/// Format timestamp for display
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
        timestamp.format("%b %d").to_string()
    }
}

/// Component for displaying a contact in the sidebar
pub fn contact_list_item(ui: &mut Ui, contact: &crate::types::User, app: &MessengerApp) {
    ui.horizontal(|ui| {
        // Contact avatar
        ui.label(
            RichText::new("👤")
                .size(16.0)
                .color(ui.style().visuals.weak_text_color()),
        );
        
        // Contact info
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(&contact.display_name)
                        .size(14.0)
                        .color(ui.style().visuals.strong_text_color()),
                );
                
                // Online status indicator
                if contact.is_online {
                    ui.label(
                        RichText::new("●")
                            .size(12.0)
                            .color(Color32::from_rgb(34, 197, 94)), // Green
                    );
                }
            });
            
            ui.label(
                RichText::new(&contact.status)
                    .size(12.0)
                    .color(ui.style().visuals.weak_text_color()),
            );
        });
    });
}
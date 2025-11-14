use egui::{Ui, ScrollArea, Frame, Margin, Color32, Layout, Align, RichText};
use crate::{
    ui::{sidebar, chat, settings},
    MessengerApp, AppView,
};


/// Shows the main layout of the app: sidebar, chat view, and settings.
pub fn show_main_layout(app: &mut MessengerApp, ui: &mut Ui) {
    // Apply global styling
    apply_global_styling(ui);
    
    // Main horizontal layout
    ui.horizontal(|ui| {
        ui.set_min_height(ui.available_height());
        
        // ============================================================================
        // SIDEBAR (Left Panel)
        // ============================================================================
        ui.vertical(|ui| {
            Frame::group(ui.style())
                .inner_margin(Margin::symmetric(8.0, 4.0))
                .show(ui, |ui| {
                    ui.set_min_width(280.0);
                    ui.set_max_width(350.0);
                    
                    ScrollArea::vertical()
                        .id_source("sidebar_scroll")
                        .show(ui, |ui| {
                            sidebar::show_sidebar(app, ui);
                        });
                });
        });
        
        // Separator with styling
        ui.separator();
        
        // ============================================================================
        // MAIN CONTENT AREA (Center Panel)
        // ============================================================================
        ui.vertical(|ui| {
            Frame::default()
                .inner_margin(Margin::symmetric(12.0, 8.0))
                .fill(ui.style().visuals.panel_fill)
                .show(ui, |ui| {
                    ui.set_min_size(ui.available_size());
                    
                    match app.current_view {
                        AppView::ChatList => {
                            show_chat_list_view(app, ui);
                        }
                        AppView::Chat => {
                            if let Some(chat_id) = &app.selected_chat_id {
                                chat::show_chat_view(app, ui, chat_id);
                            } else {
                                show_no_chat_selected_view(ui);
                            }
                        }
                        AppView::Contacts => {
                            show_contacts_view(app, ui);
                        }
                        AppView::Settings => {
                            settings::show_settings_panel(ui, &mut app.settings);
                        }
                        AppView::Auth => {
                            // This should not happen in main layout - user should be redirected to auth view
                            show_auth_fallback_view(ui);
                        }
                    }
                });
        });
        
        // ============================================================================
        // RIGHT PANEL (Settings/Details)
        // ============================================================================
        if app.show_settings || app.show_profile || app.show_create_group {
            ui.separator();
            
            ui.vertical(|ui| {
                Frame::group(ui.style())
                    .inner_margin(Margin::symmetric(12.0, 8.0))
                    .show(ui, |ui| {
                        ui.set_min_width(300.0);
                        ui.set_max_width(400.0);
                        
                        ScrollArea::vertical()
                            .id_source("right_panel_scroll")
                            .show(ui, |ui| {
                                show_right_panel(app, ui);
                            });
                    });
            });
        }
    });
    
    // Show any modal dialogs that should appear above everything
    show_modals(app, ui);
}

fn show_auth_fallback_view(ui: &mut Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(100.0);
        ui.label("Please log in to continue");
        ui.add_space(20.0);
        if ui.button("Go to Login").clicked() {
            // This would typically be handled by the parent component
        }
    });
}

// ============================================================================
// VIEW COMPONENTS
// ============================================================================

/// Shows the chat list view when no specific chat is selected
fn show_chat_list_view(app: &mut MessengerApp, ui: &mut Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(40.0);
        
        // App logo/icon
        ui.heading("💬 Private Messenger");
        ui.add_space(20.0);
        
        // Welcome message
        if let Some(user) = &app.current_user {
            ui.label(
                RichText::new(format!("Welcome back, {}!", user.display_name))
                    .size(18.0)
                    .color(ui.style().visuals.strong_text_color()),
            );
        }
        
        ui.add_space(30.0);
        
        // Quick actions
        ui.label("Quick Actions:");
        ui.add_space(10.0);
        
        ui.horizontal(|ui| {
            if ui.button("📝 New Chat").clicked() {
                app.show_create_group = true;
            }
            
            if ui.button("👥 Add Contact").clicked() {
                // TODO: Implement add contact flow
                app.show_notification(
                    "Feature Coming Soon".to_string(),
                    "Contact addition will be available soon".to_string(),
                    crate::types::NotificationType::Info,
                    None,
                );
            }
        });
        
        ui.add_space(20.0);
        
        // Recent chats section
        if !app.chats.is_empty() {
            ui.separator();
            ui.add_space(10.0);
            
            ui.label(
                RichText::new("Recent Chats")
                    .size(16.0)
                    .color(ui.style().visuals.strong_text_color()),
            );
            
            ScrollArea::vertical()
                .id_source("recent_chats")
                .show(ui, |ui| {
                    for chat in app.chats.values().take(5) {
                        show_chat_preview_item(ui, chat, app);
                    }
                });
        }
    });
}

/// Shows a preview item for a chat in the chat list
fn show_chat_preview_item(ui: &mut Ui, chat: &crate::types::Chat, app: &MessengerApp) {
    let response = Frame::default()
        .inner_margin(Margin::symmetric(8.0, 6.0))
        .fill(ui.style().visuals.faint_bg_color)
        .rounding(8.0)
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                // Chat icon based on type
                let icon = match chat.r#type {
                    crate::types::ChatType::Private => "👤",
                    crate::types::ChatType::Group => "👥",
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
                                .color(ui.style().visuals.strong_text_color()),
                        );
                        
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if let Some(unread_count) = chat.unread_count {
                                if unread_count > 0 {
                                    ui.label(
                                        RichText::new(unread_count.to_string())
                                            .size(12.0)
                                            .color(Color32::WHITE)
                                            .background_color(Color32::from_rgb(239, 68, 68)),
                                    );
                                }
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
                });
            });
        })
        .response;
    
    if response.clicked() {
        // This would typically select the chat
    }
}

/// Shows the view when no chat is selected
fn show_no_chat_selected_view(ui: &mut Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(100.0);
        
        ui.label(
            RichText::new("💬")
                .size(64.0)
                .color(ui.style().visuals.weak_text_color()),
        );
        
        ui.add_space(20.0);
        
        ui.label(
            RichText::new("Select a conversation")
                .size(18.0)
                .color(ui.style().visuals.strong_text_color()),
        );
        
        ui.label(
            RichText::new("Choose a chat from the sidebar to start messaging")
                .size(14.0)
                .color(ui.style().visuals.weak_text_color()),
        );
    });
}

/// Shows the contacts view
fn show_contacts_view(app: &mut MessengerApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.heading("👥 Contacts");
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.button("➕ Add Contact").clicked() {
                // TODO: Implement add contact modal
            }
        });
    });
    
    ui.separator();
    ui.add_space(10.0);
    
    if app.contacts.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(50.0);
            ui.label("No contacts yet");
            ui.label("Add some contacts to start chatting");
            ui.add_space(20.0);
            if ui.button("Add Your First Contact").clicked() {
                // TODO: Implement add contact flow
            }
        });
    } else {
        ScrollArea::vertical()
            .id_source("contacts_list")
            .show(ui, |ui| {
                for contact in &app.contacts {
                    show_contact_list_item(ui, contact, app);
                }
            });
    }
}

/// Shows a contact list item
fn show_contact_list_item(ui: &mut Ui, contact: &crate::types::User, _app: &MessengerApp) {
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
                            .color(Color32::from_rgb(34, 197, 94)),
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

/// Shows the right panel (settings, profile, group creation)
fn show_right_panel(app: &mut MessengerApp, ui: &mut Ui) {
    ui.vertical(|ui| {
        // Header with close button
        ui.horizontal(|ui| {
            let title = if app.show_settings {
                "⚙️ Settings"
            } else if app.show_profile {
                "👤 Profile"
            } else if app.show_create_group {
                "👥 Create Group"
            } else {
                ""
            };
            
            ui.heading(title);
            
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("✕").clicked() {
                    app.show_settings = false;
                    app.show_profile = false;
                    app.show_create_group = false;
                }
            });
        });
        
        ui.separator();
        ui.add_space(10.0);
        
        // Content based on what's being shown
        if app.show_settings {
            settings::show_settings_panel(ui, &mut app.settings);
        } else if app.show_profile {
            show_profile_panel(app, ui);
        } else if app.show_create_group {
            show_create_group_panel(app, ui);
        }
    });
}

/// Shows the user profile panel
fn show_profile_panel(app: &mut MessengerApp, ui: &mut Ui) {
    if let Some(user) = &app.current_user {
        ui.vertical_centered(|ui| {
            // Avatar
            if let Some(avatar_url) = &user.avatar_url {
                // TODO: Load and display actual avatar
                ui.label("🖼️ [Avatar Placeholder]");
            } else {
                ui.label(
                    RichText::new("👤")
                        .size(64.0)
                        .color(ui.style().visuals.strong_text_color()),
                );
            }
            
            ui.add_space(10.0);
            
            // User info
            ui.label(
                RichText::new(&user.display_name)
                    .size(18.0)
                    .color(ui.style().visuals.strong_text_color()),
            );
            
            ui.label(
                RichText::new(format!("@{}", user.username))
                    .size(14.0)
                    .color(ui.style().visuals.weak_text_color()),
            );
            
            ui.add_space(5.0);
            
            // Status
            ui.label(&user.status);
            
            ui.add_space(20.0);
            
            // Online status
            ui.horizontal(|ui| {
                let status_color = if user.is_online {
                    Color32::from_rgb(34, 197, 94) // Green
                } else {
                    Color32::from_rgb(156, 163, 175) // Gray
                };
                
                ui.colored_label(status_color, if user.is_online { "● Online" } else { "● Offline" });
            });
            
            ui.add_space(20.0);
            
            // Edit profile button
            if ui.button("✏️ Edit Profile").clicked() {
                // TODO: Implement profile editing
            }
        });
    }
}

/// Shows the group creation panel
fn show_create_group_panel(app: &mut MessengerApp, ui: &mut Ui) {
    ui.vertical(|ui| {
        // Group name
        ui.label("Group Name");
        ui.add_space(5.0);
        ui.text_edit_singleline(&mut app.group_form.title);
        
        ui.add_space(15.0);
        
        // Description
        ui.label("Description (Optional)");
        ui.add_space(5.0);
        ui.text_edit_multiline(&mut app.group_form.description);
        
        ui.add_space(15.0);
        
        // Member selection
        ui.label("Add Members");
        ui.add_space(5.0);
        
        if app.contacts.is_empty() {
            ui.label("No contacts available. Add some contacts first.");
        } else {
            ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    for contact in &app.contacts {
                        let mut is_selected = app.group_form.selected_members.contains(&contact.id);
                        if ui.checkbox(&mut is_selected, &contact.display_name).changed() {
                            if is_selected {
                                app.group_form.selected_members.push(contact.id.clone());
                            } else {
                                app.group_form.selected_members.retain(|id| id != &contact.id);
                            }
                        }
                    }
                });
        }
        
        ui.add_space(20.0);
        
        // Create button
        if ui.button("Create Group").clicked() {
            if app.group_form.title.trim().is_empty() {
                app.group_form.error = Some("Group name is required".to_string());
            } else if app.group_form.selected_members.is_empty() {
                app.group_form.error = Some("Select at least one member".to_string());
            } else {
                // TODO: Implement group creation
                app.show_notification(
                    "Group Created".to_string(),
                    format!("Group '{}' created successfully", app.group_form.title),
                    crate::types::NotificationType::Success,
                    None,
                );
                app.show_create_group = false;
                app.group_form = crate::types::GroupForm::default();
            }
        }
        
        // Show error if any
        if let Some(error) = &app.group_form.error {
            ui.colored_label(Color32::from_rgb(239, 68, 68), error);
        }
    });
}

/// Shows error views
fn show_error_view(ui: &mut Ui, message: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(100.0);
        
        ui.label(
            RichText::new("⚠️")
                .size(48.0)
                .color(Color32::from_rgb(251, 191, 36)),
        );
        
        ui.add_space(20.0);
        
        ui.label(
            RichText::new(message)
                .size(16.0)
                .color(ui.style().visuals.strong_text_color()),
        );
    });
}

/// Shows modal dialogs
fn show_modals(_app: &mut MessengerApp, _ui: &mut Ui) {
    // Example: Show a confirmation dialog for important actions
    // if app.show_confirmation_dialog {
    //     components::confirmation_dialog(ui, app);
    // }
}

// ============================================================================
// STYLING
// ============================================================================

/// Applies global styling to the UI
fn apply_global_styling(ui: &mut Ui) {
    let style = ui.style_mut();
    
    // Improve spacing and visuals
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    
    // Better text styles
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::proportional(18.0),
    );
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::proportional(14.0),
    );
    style.text_styles.insert(
        egui::TextStyle::Small,
        egui::FontId::proportional(12.0),
    );
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

/// Checks if the current UI context is in mobile mode
fn is_mobile_mode(ui: &Ui) -> bool {
    ui.available_width() < 600.0
}

/// Adapts layout based on screen size
fn responsive_layout(ui: &mut Ui, content: impl FnOnce(&mut Ui)) {
    if is_mobile_mode(ui) {
        ui.vertical(content);
    } else {
        ui.horizontal(content);
    }
}
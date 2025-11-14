use egui::{Ui, TextEdit, Button, Layout, Color32, RichText, FontId, CentralPanel, Frame, Margin};
use crate::{MessengerApp, AuthForm};

/// Render the authentication view (login/register form)
pub fn show_auth_view(app: &mut MessengerApp, ctx: &egui::Context) {
    CentralPanel::default().show(ctx, |ui| {
        // Center the auth form
        ui.vertical_centered(|ui| {
            ui.add_space(50.0);
            
            Frame::window(ui.style())
                .inner_margin(Margin::symmetric(20.0, 30.0))
                .show(ui, |ui| {
                    ui.set_max_width(400.0);
                    
                    show_auth_form(ui, app);
                });
        });
    });
}

/// Show the actual authentication form
fn show_auth_form(ui: &mut Ui, app: &mut MessengerApp) {
    let form = &mut app.auth_form;
    
    // Header
    ui.vertical_centered(|ui| {
        // App logo/icon
        ui.heading(
            RichText::new("💬 Private Messenger")
                .size(24.0)
                .color(ui.style().visuals.strong_text_color()),
        );
        
        ui.add_space(10.0);
        
        // Form title
        ui.label(
            RichText::new(if app.auth_view == crate::types::AuthView::Login {
                "Welcome Back"
            } else {
                "Create Account"
            })
            .size(18.0)
            .color(ui.style().visuals.strong_text_color()),
        );
        
        ui.label(
            RichText::new(if app.auth_view == crate::types::AuthView::Login {
                "Sign in to your account to continue"
            } else {
                "Create a new account to get started"
            })
            .size(14.0)
            .color(ui.style().visuals.weak_text_color()),
        );
    });
    
    ui.add_space(20.0);
    
    // Error message
    if let Some(error) = &form.error {
        Frame::default()
            .fill(Color32::from_rgba_premultiplied(239, 68, 68, 30)) // Red with transparency
            .inner_margin(Margin::symmetric(12.0, 8.0))
            .rounding(8.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("⚠️");
                    ui.label(
                        RichText::new(error)
                            .color(Color32::from_rgb(239, 68, 68))
                            .size(14.0),
                    );
                });
            });
        ui.add_space(10.0);
    }
    
    // Form fields
    ui.vertical(|ui| {
        // Username
        ui.label("Username");
        ui.add_space(4.0);
        let username_response = ui.add(
            TextEdit::singleline(&mut form.username)
                .hint_text("Enter your username")
                .desired_width(f32::INFINITY),
        );
        
        ui.add_space(12.0);
        
        // Password
        ui.label("Password");
        ui.add_space(4.0);
        let password_response = ui.add(
            TextEdit::singleline(&mut form.password)
                .password(true)
                .hint_text("Enter your password")
                .desired_width(f32::INFINITY),
        );
        
        // Additional fields for registration
        if app.auth_view == crate::types::AuthView::Register {
            ui.add_space(12.0);
            
            // Display Name
            ui.label("Display Name");
            ui.add_space(4.0);
            ui.add(
                TextEdit::singleline(&mut form.display_name)
                    .hint_text("How others will see you")
                    .desired_width(f32::INFINITY),
            );
            
            ui.add_space(12.0);
            
            // Phone Number (Optional)
            ui.label("Phone Number (Optional)");
            ui.add_space(4.0);
            ui.add(
                TextEdit::singleline(&mut form.phone_number)
                    .hint_text("+1 234 567 8900")
                    .desired_width(f32::INFINITY),
            );
        }
        
        ui.add_space(20.0);
        
        // Submit button
        let button_text = if app.auth_view == crate::types::AuthView::Login {
            if form.loading {
                "Signing In..."
            } else {
                "Sign In"
            }
        } else {
            if form.loading {
                "Creating Account..."
            } else {
                "Create Account"
            }
        };
        
        let button_enabled = !form.loading && 
                            !form.username.trim().is_empty() && 
                            !form.password.trim().is_empty() &&
                            (app.auth_view == crate::types::AuthView::Login || 
                             !form.display_name.trim().is_empty());
        
        let button_response = ui.add_enabled(
            button_enabled,
            Button::new(
                RichText::new(button_text)
                    .size(16.0)
                    .color(if button_enabled {
                        Color32::WHITE
                    } else {
                        ui.style().visuals.weak_text_color()
                    }),
            )
            .fill(if button_enabled {
                Color32::from_rgb(59, 130, 246) // Primary color
            } else {
                ui.style().visuals.faint_bg_color
            })
            .min_size(egui::vec2(ui.available_width(), 40.0)),
        );
        
        // Handle form submission on button click or Enter key
        if (button_response.clicked() || 
            (username_response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) ||
            (password_response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))) 
            && button_enabled 
        {
            handle_auth_submit(app);
        }
        
        ui.add_space(15.0);
        
        // Toggle between login/register
        ui.vertical_centered(|ui| {
            ui.horizontal(|ui| {
                if app.auth_view == crate::types::AuthView::Login {
                    ui.label("Don't have an account?");
                    if ui.link("Sign up").clicked() {
                        app.auth_view = crate::types::AuthView::Register;
                        form.error = None;
                    }
                } else {
                    ui.label("Already have an account?");
                    if ui.link("Sign in").clicked() {
                        app.auth_view = crate::types::AuthView::Login;
                        form.error = None;
                    }
                }
            });
        });
        
        // Demo credentials hint (remove in production)
        #[cfg(debug_assertions)]
        {
            ui.add_space(20.0);
            ui.separator();
            ui.vertical_centered(|ui| {
                ui.label(
                    RichText::new("Demo Credentials")
                        .size(12.0)
                        .color(ui.style().visuals.weak_text_color()),
                );
                ui.label(
                    RichText::new("Username: demo, Password: demo123")
                        .size(10.0)
                        .color(ui.style().visuals.weak_text_color()),
                );
            });
        }
    });
}

/// Handle authentication form submission
fn handle_auth_submit(app: &mut MessengerApp) {
    let form = &mut app.auth_form;
    
    // Basic validation
    if form.username.trim().is_empty() {
        form.error = Some("Username is required".to_string());
        return;
    }
    
    if form.password.trim().is_empty() {
        form.error = Some("Password is required".to_string());
        return;
    }
    
    if app.auth_view == crate::types::AuthView::Register && form.display_name.trim().is_empty() {
        form.error = Some("Display name is required".to_string());
        return;
    }
    
    // Password strength check for registration
    if app.auth_view == crate::types::AuthView::Register && form.password.len() < 8 {
        form.error = Some("Password must be at least 8 characters long".to_string());
        return;
    }
    
    // Clear previous errors
    form.error = None;
    form.loading = true;
    
    // Clone data for async operation
    let username = form.username.clone();
    let password = form.password.clone();
    let display_name = form.display_name.clone();
    let phone_number = form.phone_number.clone();
    let is_login = matches!(app.auth_view, crate::types::AuthView::Login);
    
    let network = app.network.clone();
    let event_tx = app.event_tx.clone();
    
    // Spawn async authentication task
    app.runtime.spawn(async move {
        let result = if is_login {
            network.login(&username, &password).await
        } else {
            network.register(&username, &password, &display_name, 
                           if phone_number.trim().is_empty() { None } else { Some(&phone_number) }).await
        };
        
        match result {
            Ok(auth_response) => {
                let event = if is_login {
                    crate::types::AppEvent::LoginSuccess(auth_response)
                } else {
                    crate::types::AppEvent::RegisterSuccess(auth_response)
                };
                let _ = event_tx.send(event);
            }
            Err(e) => {
                let error_event = if is_login {
                    crate::types::AppEvent::LoginError(e.to_string())
                } else {
                    crate::types::AppEvent::RegisterError(e.to_string())
                };
                let _ = event_tx.send(error_event);
            }
        }
    });
}

/// Helper function to reset the auth form
pub fn reset_auth_form(form: &mut AuthForm) {
    *form = AuthForm::default();
}

/// Show a loading screen during authentication
pub fn show_auth_loading(ui: &mut Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(100.0);
        
        // Spinner animation
        ui.label(
            RichText::new("⏳")
                .size(48.0)
                .color(ui.style().visuals.strong_text_color()),
        );
        
        ui.add_space(20.0);
        
        ui.label(
            RichText::new("Authenticating...")
                .size(16.0)
                .color(ui.style().visuals.strong_text_color()),
        );
        
        ui.label(
            RichText::new("Please wait while we verify your credentials")
                .size(14.0)
                .color(ui.style().visuals.weak_text_color()),
        );
    });
}

/// Show a success message after authentication
pub fn show_auth_success(ui: &mut Ui, message: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(100.0);
        
        ui.label(
            RichText::new("✅")
                .size(48.0)
                .color(Color32::from_rgb(34, 197, 94)), // Green
        );
        
        ui.add_space(20.0);
        
        ui.label(
            RichText::new("Success!")
                .size(18.0)
                .color(ui.style().visuals.strong_text_color()),
        );
        
        ui.label(
            RichText::new(message)
                .size(14.0)
                .color(ui.style().visuals.weak_text_color()),
        );
    });
}
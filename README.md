# MessengerAPP
This is a early model of my messenger application built in two parts: Server end and user end. 

A cross-platform messaging application with a Go backend server and a Rust GUI client.  
The project aims to provide a fast, lightweight, and modern messaging platform.  

**Note:** The Rust client is under development and does not compile yet.

## Features (planned)

- Real-time messaging via Go server
- Rust GUI using `egui`
- Asynchronous networking with `tokio`
- Support for text, images, and media messages
- Modern, user-friendly interface

## Architecture

- **Server (Go):** Handles message routing, storage, and network communication  
- **Client (Rust):** GUI, client-side logic, and async networking (work in progress)  
- **Frontend GUI (Rust + egui):** Lightweight and responsive interface (work in progress)

## Getting Started

### Prerequisites

- Go (latest stable)
- Rust (latest stable, with Cargo)
- Dependencies specified in `Cargo.toml` (e.g., `tokio`, `egui`)

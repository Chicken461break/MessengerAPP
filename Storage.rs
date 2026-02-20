use rusqlite::{Connection, params};
use crate::types::*;
use anyhow::{Result, Context};
use std::path::PathBuf;

pub struct StorageManager {
    conn: Connection,
}

impl StorageManager {
    pub fn new() -> Result<Self> {
        let db_path = Self::get_db_path()?;

        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&db_path)
            .context("Failed to open database")?;

        // Enable WAL mode for better concurrent access
        conn.execute("PRAGMA journal_mode=WAL", [])?;
        conn.execute("PRAGMA foreign_keys=ON", [])?;

        Self::create_tables(&conn)?;

        Ok(Self { conn })
    }

    fn get_db_path() -> Result<PathBuf> {
        let mut path = dirs::data_local_dir()
            .ok_or_else(|| anyhow::anyhow!("Cannot determine data directory"))?;
        path.push("private-messenger");
        path.push("client.db");
        Ok(path)
    }

    fn create_tables(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS session (
                key TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                display_name TEXT NOT NULL,
                token TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chats_cache (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages_cache (
                id TEXT PRIMARY KEY,
                chat_id TEXT NOT NULL,
                data TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                FOREIGN KEY (chat_id) REFERENCES chats_cache(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS contacts_cache (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS file_cache (
                media_url TEXT PRIMARY KEY,
                local_path TEXT NOT NULL,
                mime_type TEXT,
                size INTEGER,
                downloaded_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages_cache(chat_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages_cache(timestamp DESC);
            "
        )?;

        Ok(())
    }

    // ========================================================================
    // SESSION MANAGEMENT
    // ========================================================================

    pub async fn save_session(&mut self, token: &str, user: &User) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO session (key, user_id, username, display_name, token, created_at) 
             VALUES ('current', ?, ?, ?, ?, ?)",
            params![
                user.id,
                user.username,
                user.display_name,
                token,
                chrono::Utc::now().timestamp()
            ],
        )?;

        Ok(())
    }

    pub async fn load_session(&self) -> Result<Option<(String, User)>> {
        let result = self.conn.query_row(
            "SELECT token, user_id, username, display_name FROM session WHERE key = 'current'",
            [],
            |row| {
                let token: String = row.get(0)?;
                let user = User {
                    id: row.get(1)?,
                    username: row.get(2)?,
                    display_name: row.get(3)?,
                    phone_number: None,
                    status: String::new(),
                    avatar_url: None,
                    last_seen: chrono::Utc::now(),
                    is_online: false,
                    public_key: None,
                };
                Ok((token, user))
            },
        );

        match result {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn clear_session(&mut self) -> Result<()> {
        self.conn.execute("DELETE FROM session", [])?;
        Ok(())
    }

    // ========================================================================
    // SETTINGS
    // ========================================================================

    pub async fn save_settings(&mut self, settings: &AppSettings) -> Result<()> {
        let json = serde_json::to_string(settings)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('app_settings', ?)",
            params![json],
        )?;
        Ok(())
    }

    pub async fn load_settings(&self) -> Result<AppSettings> {
        let json: String = self.conn.query_row(
            "SELECT value FROM settings WHERE key = 'app_settings'",
            [],
            |row| row.get(0),
        )?;

        Ok(serde_json::from_str(&json)?)
    }

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    pub async fn cache_chat(&mut self, chat: &Chat) -> Result<()> {
        let json = serde_json::to_string(chat)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO chats_cache (id, data, updated_at) VALUES (?, ?, ?)",
            params![chat.id, json, chrono::Utc::now().timestamp()],
        )?;
        Ok(())
    }

    pub async fn load_cached_chats(&self) -> Result<Vec<Chat>> {
        let mut stmt = self.conn.prepare(
            "SELECT data FROM chats_cache ORDER BY updated_at DESC"
        )?;

        let chats = stmt.query_map([], |row| {
            let json: String = row.get(0)?;
            Ok(json)
        })?
        .filter_map(|r| r.ok())
        .filter_map(|json| serde_json::from_str(&json).ok())
        .collect();

        Ok(chats)
    }

    pub async fn cache_message(&mut self, message: &Message) -> Result<()> {
        let json = serde_json::to_string(message)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO messages_cache (id, chat_id, data, timestamp) VALUES (?, ?, ?, ?)",
            params![message.id, message.chat_id, json, message.timestamp.timestamp()],
        )?;
        Ok(())
    }

    pub async fn load_cached_messages(&self, chat_id: &str, limit: usize) -> Result<Vec<Message>> {
        let mut stmt = self.conn.prepare(
            "SELECT data FROM messages_cache WHERE chat_id = ? ORDER BY timestamp DESC LIMIT ?"
        )?;

        let messages = stmt.query_map(params![chat_id, limit], |row| {
            let json: String = row.get(0)?;
            Ok(json)
        })?
        .filter_map(|r| r.ok())
        .filter_map(|json| serde_json::from_str(&json).ok())
        .collect();

        Ok(messages)
    }

    pub async fn cache_file(&mut self, media_url: &str, local_path: &str, mime_type: Option<&str>, size: Option<u64>) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO file_cache (media_url, local_path, mime_type, size, downloaded_at) VALUES (?, ?, ?, ?, ?)",
            params![media_url, local_path, mime_type, size.map(|s| s as i64), chrono::Utc::now().timestamp()],
        )?;
        Ok(())
    }

    pub async fn get_cached_file(&self, media_url: &str) -> Result<Option<String>> {
        let result = self.conn.query_row(
            "SELECT local_path FROM file_cache WHERE media_url = ?",
            params![media_url],
            |row| row.get(0),
        );

        match result {
            Ok(path) => Ok(Some(path)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn clear_cache(&mut self) -> Result<()> {
        self.conn.execute_batch(
            "DELETE FROM chats_cache;
             DELETE FROM messages_cache;
             DELETE FROM contacts_cache;
             DELETE FROM file_cache;"
        )?;
        Ok(())
    }

    pub async fn clear_old_cache(&mut self, days: i64) -> Result<usize> {
        let cutoff = chrono::Utc::now().timestamp() - (days * 24 * 60 * 60);

        let deleted = self.conn.execute(
            "DELETE FROM messages_cache WHERE timestamp < ?",
            params![cutoff],
        )?;

        Ok(deleted)
    }
}
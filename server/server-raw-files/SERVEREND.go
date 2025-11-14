package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/robfig/cron/v3"
	"github.com/spf13/afero"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Metrics
var (
	websocketConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "websocket_connections_total",
		Help: "Total number of active WebSocket connections",
	})

	activeUsers = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "active_users_total",
		Help: "Total number of active users",
	})

	privateChatsGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "private_chats_total",
		Help: "Total number of active private chats",
	})

	groupChatsGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "group_chats_total",
		Help: "Total number of active group chats",
	})

	messagesProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "messages_processed_total",
		Help: "Total number of messages processed",
	}, []string{"type", "chat_type"})

	fileUploads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "file_uploads_total",
		Help: "Total number of file uploads",
	}, []string{"status"})

	callMetrics = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "calls_total",
		Help: "Total number of calls initiated",
	}, []string{"type", "status"})

	apiDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "api_request_duration_seconds",
		Help:    "API request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"endpoint", "method"})
)

var (
	upgrader websocket.Upgrader
	logger   *zap.Logger
	fs       = afero.NewOsFs()
	db       *sql.DB
)

type Config struct {
	Server struct {
		Host           string        `mapstructure:"host"`
		Port           int           `mapstructure:"port"`
		ReadTimeout    time.Duration `mapstructure:"read_timeout"`
		WriteTimeout   time.Duration `mapstructure:"write_timeout"`
		IdleTimeout    time.Duration `mapstructure:"idle_timeout"`
		MaxHeaderBytes int           `mapstructure:"max_header_bytes"`
		AllowedOrigins []string      `mapstructure:"allowed_origins"`
	} `mapstructure:"server"`

	Security struct {
		JWTSecret           string        `mapstructure:"jwt_secret"`
		JWTPrivateKeyPath   string        `mapstructure:"jwt_private_key_path"`
		JWTPublicKeyPath    string        `mapstructure:"jwt_public_key_path"`
		JWTExpiryMinutes    time.Duration `mapstructure:"jwt_expiry_minutes"`
		PasswordAlgorithm   string        `mapstructure:"password_algorithm"`
		BCryptCost          int           `mapstructure:"bcrypt_cost"`
		Argon2Params        Argon2Params  `mapstructure:"argon2_params"`
		RateLimitPerSecond  int           `mapstructure:"rate_limit_per_second"`
		MessageEncryption   bool          `mapstructure:"message_encryption"`
	} `mapstructure:"security"`

	Media struct {
		MaxUploadSize    int64    `mapstructure:"max_upload_size"`
		UploadPath       string   `mapstructure:"upload_path"`
		RetentionDays    int      `mapstructure:"retention_days"`
		AllowedMimeTypes []string `mapstructure:"allowed_mime_types"`
		AllowedExtensions []string `mapstructure:"allowed_extensions"`
	} `mapstructure:"media"`

	Database struct {
		Path         string `mapstructure:"path"`
		MaxOpenConns int    `mapstructure:"max_open_conns"`
		MaxIdleConns int    `mapstructure:"max_idle_conns"`
	} `mapstructure:"database"`

	Limits struct {
		MaxGroupSize      int `mapstructure:"max_group_size"`
		MaxContacts       int `mapstructure:"max_contacts"`
		MaxMessageLength  int `mapstructure:"max_message_length"`
		CallTimeoutSec    int `mapstructure:"call_timeout_sec"`
	} `mapstructure:"limits"`
}

type Argon2Params struct {
	Memory      uint32 `mapstructure:"memory"`
	Iterations  uint32 `mapstructure:"iterations"`
	Parallelism uint8  `mapstructure:"parallelism"`
	SaltLength  uint32 `mapstructure:"salt_length"`
	KeyLength   uint32 `mapstructure:"key_length"`
}

var cfg Config
var jwtPrivateKey *rsa.PrivateKey
var jwtPublicKey *rsa.PublicKey

const (
	ChatTypePrivate = "private"
	ChatTypeGroup   = "group"
)

const (
	MessageTypeText         = "text"
	MessageTypeImage        = "image"
	MessageTypeVoice        = "voice"
	MessageTypeVideo        = "video"
	MessageTypeCallOffer    = "call_offer"
	MessageTypeCallAnswer   = "call_answer"
	MessageTypeICECandidate = "ice_candidate"
	MessageTypeCallEnd      = "call_end"
	MessageTypeSystem       = "system"
)

const (
	CallTypeVoice = "voice"
	CallTypeVideo = "video"
)

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PhoneNumber  string    `json:"phone_number,omitempty"`
	DisplayName  string    `json:"display_name"`
	Status       string    `json:"status"`
	AvatarURL    string    `json:"avatar_url,omitempty"`
	LastSeen     time.Time `json:"last_seen"`
	IsOnline     bool      `json:"is_online"`
	PublicKey    string    `json:"public_key,omitempty"`
}

type Chat struct {
	ID             string       `json:"id"`
	Type           string       `json:"type"`
	Title          string       `json:"title"`
	Description    string       `json:"description,omitempty"`
	CreatedBy      string       `json:"created_by"`
	CreatedAt      time.Time    `json:"created_at"`
	LastActivity   time.Time    `json:"last_activity"`
	AvatarURL      string       `json:"avatar_url,omitempty"`
	Members        []ChatMember `json:"members,omitempty"`
	Admins         []string     `json:"admins,omitempty"`
	ParticipantIDs []string     `json:"participant_ids,omitempty"`
}

type ChatMember struct {
	UserID      string    `json:"user_id"`
	JoinedAt    time.Time `json:"joined_at"`
	Role        string    `json:"role"`
	DisplayName string    `json:"display_name,omitempty"`
}

type Message struct {
	ID           string        `json:"id"`
	ChatID       string        `json:"chat_id"`
	SenderID     string        `json:"sender_id"`
	Type         string        `json:"type"`
	Content      string        `json:"content,omitempty"`
	MediaURL     string        `json:"media_url,omitempty"`
	Timestamp    time.Time     `json:"timestamp"`
	Edited       bool          `json:"edited"`
	EditedAt     *time.Time    `json:"edited_at,omitempty"`
	ReplyTo      *string       `json:"reply_to,omitempty"`
	Encrypted    bool          `json:"encrypted"`
	CallMetadata *CallMetadata `json:"call_metadata,omitempty"`
}

type CallMetadata struct {
	CallType      string                   `json:"call_type"`
	CallID        string                   `json:"call_id"`
	SDPOffer      map[string]interface{}   `json:"sdp_offer,omitempty"`
	SDPAnswer     map[string]interface{}   `json:"sdp_answer,omitempty"`
	ICECandidates []map[string]interface{} `json:"ice_candidates,omitempty"`
	Duration      int                      `json:"duration,omitempty"`
}

type ActiveCall struct {
	CallID       string
	ChatID       string
	CallType     string
	InitiatorID  string
	Participants map[string]bool
	StartTime    time.Time
	Lock         sync.RWMutex
}

type SignalMessage struct {
	Type      string          `json:"type"`
	ChatID    string          `json:"chat_id,omitempty"`
	SenderID  string          `json:"sender_id,omitempty"`
	MessageID string          `json:"message_id,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	JWT       string          `json:"jwt,omitempty"`
	Timestamp int64           `json:"ts,omitempty"`
}

var (
	users = struct {
		sync.RWMutex
		m map[string]*User
	}{m: make(map[string]*User)}

	chats = struct {
		sync.RWMutex
		m map[string]*Chat
	}{m: make(map[string]*Chat)}

	connections = struct {
		sync.RWMutex
		m map[string]*websocket.Conn
	}{m: make(map[string]*websocket.Conn)}

	activeCalls = struct {
		sync.RWMutex
		m map[string]*ActiveCall
	}{m: make(map[string]*ActiveCall)}

	userChats = struct {
		sync.RWMutex
		m map[string]map[string]bool
	}{m: make(map[string]map[string]bool)}
)

func init() {
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}
}

func initConfig() error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/private-messaging/")

	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8443)
	viper.SetDefault("server.read_timeout", 15*time.Second)
	viper.SetDefault("server.write_timeout", 15*time.Second)
	viper.SetDefault("server.idle_timeout", 60*time.Second)
	viper.SetDefault("server.allowed_origins", []string{"https://yourdomain.com"})
	
	viper.SetDefault("security.jwt_expiry_minutes", 1440)
	viper.SetDefault("security.password_algorithm", "bcrypt")
	viper.SetDefault("security.bcrypt_cost", 12)
	viper.SetDefault("security.rate_limit_per_second", 100)
	viper.SetDefault("security.message_encryption", true)
	viper.SetDefault("security.argon2_params.memory", 64*1024)
	viper.SetDefault("security.argon2_params.iterations", 3)
	viper.SetDefault("security.argon2_params.parallelism", 2)
	viper.SetDefault("security.argon2_params.salt_length", 16)
	viper.SetDefault("security.argon2_params.key_length", 32)
	
	viper.SetDefault("media.max_upload_size", 50*1024*1024)
	viper.SetDefault("media.upload_path", "./uploads")
	viper.SetDefault("media.retention_days", 30)
	viper.SetDefault("media.allowed_mime_types", []string{
		"image/jpeg", "image/png", "image/gif", 
		"audio/mpeg", "audio/wav", "video/mp4",
	})
	viper.SetDefault("media.allowed_extensions", []string{
		".jpg", ".jpeg", ".png", ".gif", ".mp3", ".wav", ".mp4",
	})
	
	viper.SetDefault("database.path", "./messaging.db")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)
	
	viper.SetDefault("limits.max_group_size", 100)
	viper.SetDefault("limits.max_contacts", 1000)
	viper.SetDefault("limits.max_message_length", 4096)
	viper.SetDefault("limits.call_timeout_sec", 30)

	viper.AutomaticEnv()
	viper.SetEnvPrefix("MESSAGING")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logger.Warn("Config file not found, using defaults and environment variables")
		} else {
			return fmt.Errorf("error reading config: %w", err)
		}
	}

	if err := viper.Unmarshal(&cfg); err != nil {
		return fmt.Errorf("error unmarshaling config: %w", err)
	}

	if err := initJWTKeys(); err != nil {
		return fmt.Errorf("error initializing JWT keys: %w", err)
	}

	upgrader = websocket.Upgrader{
		CheckOrigin:     checkOrigin,
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	return nil
}

func initJWTKeys() error {
	if cfg.Security.JWTPrivateKeyPath != "" && cfg.Security.JWTPublicKeyPath != "" {
		privateKeyData, err := os.ReadFile(cfg.Security.JWTPrivateKeyPath)
		if err != nil {
			return fmt.Errorf("error reading private key: %w", err)
		}

		publicKeyData, err := os.ReadFile(cfg.Security.JWTPublicKeyPath)
		if err != nil {
			return fmt.Errorf("error reading public key: %w", err)
		}

		jwtPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
		if err != nil {
			return fmt.Errorf("error parsing private key: %w", err)
		}

		jwtPublicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
		if err != nil {
			return fmt.Errorf("error parsing public key: %w", err)
		}

		logger.Info("Loaded RSA keys for JWT signing")
		return nil
	}

	if cfg.Security.JWTSecret == "" {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return fmt.Errorf("error generating JWT secret: %w", err)
		}
		cfg.Security.JWTSecret = base64.URLEncoding.EncodeToString(secret)
		logger.Warn("Generated new JWT secret - please set MESSAGING_SECURITY_JWT_SECRET for production")
	}

	return nil
}

func checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	for _, allowedOrigin := range cfg.Server.AllowedOrigins {
		if origin == allowedOrigin {
			return true
		}
	}

	logger.Warn("Blocked WebSocket connection from unauthorized origin", 
		zap.String("origin", origin),
		zap.Strings("allowed_origins", cfg.Server.AllowedOrigins))
	return false
}

func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", cfg.Database.Path+"?_journal_mode=WAL&_timeout=5000")
	if err != nil {
		return fmt.Errorf("error opening database: %w", err)
	}

	db.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	db.SetMaxIdleConns(cfg.Database.MaxIdleConns)

	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			phone_number TEXT UNIQUE,
			display_name TEXT NOT NULL,
			status TEXT DEFAULT 'Hey there! I am using Private Messenger',
			avatar_url TEXT,
			password_hash TEXT NOT NULL,
			public_key TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS chats (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL CHECK(type IN ('private', 'group')),
			title TEXT,
			description TEXT,
			created_by TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
			avatar_url TEXT,
			FOREIGN KEY (created_by) REFERENCES users (id)
		)`,

		`CREATE TABLE IF NOT EXISTS chat_members (
			chat_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			role TEXT DEFAULT 'member' CHECK(role IN ('admin', 'member')),
			display_name TEXT,
			PRIMARY KEY (chat_id, user_id),
			FOREIGN KEY (chat_id) REFERENCES chats (id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
		)`,

		`CREATE TABLE IF NOT EXISTS messages (
			id TEXT PRIMARY KEY,
			chat_id TEXT NOT NULL,
			sender_id TEXT NOT NULL,
			type TEXT NOT NULL,
			content TEXT,
			media_url TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			edited BOOLEAN DEFAULT FALSE,
			edited_at DATETIME,
			reply_to TEXT,
			encrypted BOOLEAN DEFAULT FALSE,
			FOREIGN KEY (chat_id) REFERENCES chats (id) ON DELETE CASCADE,
			FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE
		)`,

		`CREATE TABLE IF NOT EXISTS contacts (
			id TEXT PRIMARY KEY,
			owner_id TEXT NOT NULL,
			contact_id TEXT NOT NULL,
			display_name TEXT,
			added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_blocked BOOLEAN DEFAULT FALSE,
			FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE,
			FOREIGN KEY (contact_id) REFERENCES users (id) ON DELETE CASCADE,
			UNIQUE(owner_id, contact_id)
		)`,

		`CREATE TABLE IF NOT EXISTS calls (
			id TEXT PRIMARY KEY,
			chat_id TEXT NOT NULL,
			call_type TEXT NOT NULL,
			initiator_id TEXT NOT NULL,
			start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
			end_time DATETIME,
			duration INTEGER,
			status TEXT DEFAULT 'completed',
			FOREIGN KEY (chat_id) REFERENCES chats (id) ON DELETE CASCADE,
			FOREIGN KEY (initiator_id) REFERENCES users (id) ON DELETE CASCADE
		)`,

		`CREATE INDEX IF NOT EXISTS idx_messages_chat_timestamp ON messages(chat_id, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)`,
		`CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_members(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_contacts_owner ON contacts(owner_id)`,
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		`CREATE INDEX IF NOT EXISTS idx_chats_last_activity ON chats(last_activity)`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("error creating table/index: %w", err)
		}
	}

	return nil
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

func NewToken(userID string) (string, error) {
	var token *jwt.Token
	
	if jwtPrivateKey != nil {
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": userID,
			"exp": time.Now().Add(time.Minute * time.Duration(cfg.Security.JWTExpiryMinutes)).Unix(),
			"iat": time.Now().Unix(),
			"iss": "private-messaging-server",
		})
		return token.SignedString(jwtPrivateKey)
	} else {
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": userID,
			"exp": time.Now().Add(time.Minute * time.Duration(cfg.Security.JWTExpiryMinutes)).Unix(),
			"iat": time.Now().Unix(),
			"iss": "private-messaging-server",
		})
		return token.SignedString([]byte(cfg.Security.JWTSecret))
	}
}

func ValidateToken(tokenString string) (string, error) {
	var token *jwt.Token
	var err error

	if jwtPublicKey != nil {
		token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtPublicKey, nil
		})
	} else {
		token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(cfg.Security.JWTSecret), nil
		})
	}

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if err := claims.Valid(); err != nil {
			return "", err
		}
		return claims["sub"].(string), nil
	}

	return "", errors.New("invalid token")
}

func HashPassword(password string) (string, error) {
	switch cfg.Security.PasswordAlgorithm {
	case "argon2":
		return hashArgon2(password)
	default:
		return hashBcrypt(password)
	}
}

func hashBcrypt(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cfg.Security.BCryptCost)
	return string(bytes), err
}

func hashArgon2(password string) (string, error) {
	salt := make([]byte, cfg.Security.Argon2Params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		cfg.Security.Argon2Params.Iterations,
		cfg.Security.Argon2Params.Memory,
		cfg.Security.Argon2Params.Parallelism,
		cfg.Security.Argon2Params.KeyLength,
	)

	encodedHash := base64.RawStdEncoding.EncodeToString(hash)
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		cfg.Security.Argon2Params.Memory,
		cfg.Security.Argon2Params.Iterations,
		cfg.Security.Argon2Params.Parallelism,
		encodedSalt,
		encodedHash), nil
}

func CheckPasswordHash(password, hash string) bool {
	if strings.HasPrefix(hash, "$argon2id$") {
		return verifyArgon2(password, hash)
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func verifyArgon2(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	storedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		cfg.Security.Argon2Params.Iterations,
		cfg.Security.Argon2Params.Memory,
		cfg.Security.Argon2Params.Parallelism,
		cfg.Security.Argon2Params.KeyLength,
	)

	return len(computedHash) == len(storedHash) && 
	       subtleConstantTimeCompare(computedHash, storedHash)
}

func subtleConstantTimeCompare(x, y []byte) bool {
	if len(x) != len(y) {
		return false
	}
	
	var v byte
	for i := 0; i < len(x); i++ {
		v |= x[i] ^ y[i]
	}
	return v == 0
}

func sanitizeFilename(filename string) string {
	filename = filepath.Base(filename)
	reg := regexp.MustCompile(`[^a-zA-Z0-9\.\-_]`)
	filename = reg.ReplaceAllString(filename, "")
	if len(filename) > 255 {
		filename = filename[:255]
	}
	return filename
}

func validateFileExtension(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	for _, allowedExt := range cfg.Media.AllowedExtensions {
		if ext == allowedExt {
			return true
		}
	}
	return false
}

func createPrivateChat(user1ID, user2ID string) (*Chat, error) {
	chatID := generatePrivateChatID(user1ID, user2ID)
	
	chats.RLock()
	chat, exists := chats.m[chatID]
	chats.RUnlock()
	
	if exists {
		return chat, nil
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	user1, err := getUserByID(user1ID)
	if err != nil {
		return nil, err
	}
	user2, err := getUserByID(user2ID)
	if err != nil {
		return nil, err
	}

	chat = &Chat{
		ID:            chatID,
		Type:          ChatTypePrivate,
		Title:         fmt.Sprintf("%s and %s", user1.DisplayName, user2.DisplayName),
		CreatedBy:     user1ID,
		CreatedAt:     time.Now(),
		LastActivity:  time.Now(),
		ParticipantIDs: []string{user1ID, user2ID},
	}

	_, err = tx.Exec(
		"INSERT INTO chats (id, type, title, created_by) VALUES (?, ?, ?, ?)",
		chat.ID, chat.Type, chat.Title, chat.CreatedBy,
	)
	if err != nil {
		return nil, err
	}

	members := []struct {
		userID string
		role   string
	}{
		{user1ID, "member"},
		{user2ID, "member"},
	}

	for _, member := range members {
		_, err = tx.Exec(
			"INSERT INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)",
			chat.ID, member.userID, member.role,
		)
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	chats.Lock()
	chats.m[chatID] = chat
	chats.Unlock()

	updateUserChats(user1ID, chatID)
	updateUserChats(user2ID, chatID)

	privateChatsGauge.Inc()
	return chat, nil
}

func broadcastToChat(chatID string, message []byte, excludeUserID string) {
	chats.RLock()
	chat, exists := chats.m[chatID]
	chats.RUnlock()

	if !exists {
		return
	}

	var userIDs []string
	if chat.Type == ChatTypePrivate {
		userIDs = chat.ParticipantIDs
	} else {
		for _, member := range chat.Members {
			userIDs = append(userIDs, member.UserID)
		}
	}

	for _, userID := range userIDs {
		if userID == excludeUserID {
			continue
		}

		connections.RLock()
		conn, exists := connections.m[userID]
		connections.RUnlock()

		if exists && conn != nil {
			err := conn.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				logger.Warn("Failed to send message to user", 
					zap.String("user_id", userID), 
					zap.Error(err))
				
				connections.Lock()
				delete(connections.m, userID)
				connections.Unlock()
				
				websocketConnections.Dec()
				
				users.Lock()
				if user, exists := users.m[userID]; exists {
					user.IsOnline = false
					user.LastSeen = time.Now()
				}
				users.Unlock()
			}
		}
	}
}

func startCall(chatID, initiatorID, callType string) (*ActiveCall, error) {
	callID := generateID()
	call := &ActiveCall{
		CallID:       callID,
		ChatID:       chatID,
		CallType:     callType,
		InitiatorID:  initiatorID,
		Participants: make(map[string]bool),
		StartTime:    time.Now(),
	}
	
	call.Lock.Lock()
	call.Participants[initiatorID] = true
	call.Lock.Unlock()

	activeCalls.Lock()
	activeCalls.m[callID] = call
	activeCalls.Unlock()

	callMetrics.WithLabelValues(callType, "started").Inc()

	ctx, cancel := context.WithTimeout(context.Background(), 
		time.Duration(cfg.Limits.CallTimeoutSec)*time.Second)
	defer cancel()

	go func() {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				activeCalls.RLock()
				call, exists := activeCalls.m[callID]
				activeCalls.RUnlock()

				if exists {
					call.Lock.RLock()
					participantCount := len(call.Participants)
					call.Lock.RUnlock()
					
					if participantCount == 1 {
						endCall(callID, initiatorID)
					}
				}
			}
		}
	}()

	return call, nil
}

func handleWebSocketMessage(userID string, signalMsg *SignalMessage, rawMsg []byte) {
	switch signalMsg.Type {
	case "call_answer":
		var answerData struct {
			CallID string                 `json:"call_id"`
			SDP    map[string]interface{} `json:"sdp"`
		}
		if err := json.Unmarshal(signalMsg.Payload, &answerData); err != nil {
			return
		}

		answerMessage := map[string]interface{}{
			"type":    MessageTypeCallAnswer,
			"call_id": answerData.CallID,
			"sdp":     answerData.SDP,
			"user_id": userID,
		}

		answerBytes, _ := json.Marshal(answerMessage)
		activeCalls.RLock()
		call, exists := activeCalls.m[answerData.CallID]
		activeCalls.RUnlock()

		if exists {
			call.Lock.Lock()
			call.Participants[userID] = true
			call.Lock.Unlock()
			
			broadcastToChat(call.ChatID, answerBytes, userID)
		}
	}
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	token := r.URL.Query().Get("token")
	
	validatedUserID, err := ValidateToken(token)
	if err != nil || validatedUserID != userID {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Error("WebSocket upgrade failed", zap.Error(err))
		return
	}
	defer ws.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connections.Lock()
	connections.m[userID] = ws
	connections.Unlock()

	websocketConnections.Inc()

	users.Lock()
	if user, exists := users.m[userID]; exists {
		user.IsOnline = true
		user.LastSeen = time.Now()
	}
	users.Unlock()

	logger.Info("User connected", zap.String("user_id", userID))

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				_, msg, err := ws.ReadMessage()
				if err != nil {
					if websocket.IsUnexpectedCloseError(err, 
						websocket.CloseGoingAway, 
						websocket.CloseAbnormalClosure) {
						logger.Warn("WebSocket unexpected close", 
							zap.String("user_id", userID), 
							zap.Error(err))
					}
					cancel()
					return
				}

				var signalMsg SignalMessage
				if err := json.Unmarshal(msg, &signalMsg); err != nil {
					logger.Warn("Invalid message format", zap.Error(err))
					continue
				}

				handleWebSocketMessage(userID, &signalMsg, msg)
			}
		}
	}()

	<-ctx.Done()

	connections.Lock()
	delete(connections.m, userID)
	connections.Unlock()

	websocketConnections.Dec()

	users.Lock()
	if user, exists := users.m[userID]; exists {
		user.IsOnline = false
		user.LastSeen = time.Now()
	}
	users.Unlock()

	logger.Info("User disconnected", zap.String("user_id", userID))
}

func uploadMediaHandler(w http.ResponseWriter, r *http.Request) {
	// REMOVED the unused userID line that was causing the error
	// userID := r.Context().Value("userID").(string)  // THIS LINE WAS UNUSED

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, cfg.Media.MaxUploadSize)
	if err := r.ParseMultipartForm(cfg.Media.MaxUploadSize); err != nil {
		fileUploads.WithLabelValues("too_large").Inc()
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		fileUploads.WithLabelValues("missing_file").Inc()
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	buffer := make([]byte, 512)
	_, err = file.Read(buffer)
	if err != nil {
		fileUploads.WithLabelValues("read_error").Inc()
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}
	file.Seek(0, 0)

	contentType := http.DetectContentType(buffer)
	allowedMime := false
	for _, mime := range cfg.Media.AllowedMimeTypes {
		if mime == contentType {
			allowedMime = true
			break
		}
	}

	if !allowedMime {
		fileUploads.WithLabelValues("invalid_type").Inc()
		http.Error(w, "File type not allowed", http.StatusBadRequest)
		return
	}

	if !validateFileExtension(header.Filename) {
		fileUploads.WithLabelValues("invalid_extension").Inc()
		http.Error(w, "File extension not allowed", http.StatusBadRequest)
		return
	}

	safeFilename := sanitizeFilename(header.Filename)
	
	filename := fmt.Sprintf("%s_%d_%s", "user", time.Now().UnixNano(), safeFilename) // Removed userID reference
	filePath := filepath.Join(cfg.Media.UploadPath, filename)

	if !strings.HasPrefix(filepath.Clean(filePath), cfg.Media.UploadPath) {
		fileUploads.WithLabelValues("path_traversal").Inc()
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}

	if err := fs.MkdirAll(cfg.Media.UploadPath, 0755); err != nil {
		fileUploads.WithLabelValues("directory_error").Inc()
		http.Error(w, "Failed to create upload directory", http.StatusInternalServerError)
		return
	}

	dst, err := fs.Create(filePath)
	if err != nil {
		fileUploads.WithLabelValues("create_error").Inc()
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		fileUploads.WithLabelValues("save_error").Inc()
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	token, err := NewToken(filename)
	if err != nil {
		fileUploads.WithLabelValues("token_error").Inc()
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	fileUploads.WithLabelValues("success").Inc()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"filename":       filename,
		"download_token": token,
		"url":           fmt.Sprintf("/media/%s?token=%s", filename, token),
	})
}

func downloadMediaHandler(w http.ResponseWriter, r *http.Request) {
	filename := strings.TrimPrefix(r.URL.Path, "/media/")
	if filename == "" {
		http.Error(w, "Filename required", http.StatusBadRequest)
		return
	}

	filename = sanitizeFilename(filename)

	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Token required", http.StatusUnauthorized)
		return
	}

	validatedFilename, err := ValidateToken(token)
	if err != nil || validatedFilename != filename {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	filePath := filepath.Join(cfg.Media.UploadPath, filename)
	
	if !strings.HasPrefix(filepath.Clean(filePath), cfg.Media.UploadPath) {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}

	f, err := fs.Open(filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, filename, time.Now(), f)
}

func getChatsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(string)

	rows, err := db.Query(`
		SELECT c.id, c.type, c.title, c.description, c.avatar_url, c.last_activity,
			   (SELECT content FROM messages WHERE chat_id = c.id ORDER BY timestamp DESC LIMIT 1) as last_message
		FROM chats c
		INNER JOIN chat_members cm ON c.id = cm.chat_id
		WHERE cm.user_id = ?
		ORDER BY c.last_activity DESC
	`, userID)
	if err != nil {
		http.Error(w, "Failed to fetch chats", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type ChatSummary struct {
		ID           string    `json:"id"`
		Type         string    `json:"type"`
		Title        string    `json:"title"`
		Description  string    `json:"description,omitempty"`
		AvatarURL    string    `json:"avatar_url,omitempty"`
		LastActivity time.Time `json:"last_activity"`
		LastMessage  string    `json:"last_message,omitempty"`
	}

	var chats []ChatSummary
	for rows.Next() {
		var chat ChatSummary
		var lastMessage sql.NullString
		
		err := rows.Scan(
			&chat.ID,
			&chat.Type,
			&chat.Title,
			&chat.Description,
			&chat.AvatarURL,
			&chat.LastActivity,
			&lastMessage,
		)
		if err != nil {
			logger.Error("Failed to scan chat row", zap.Error(err))
			continue
		}
		
		if lastMessage.Valid {
			chat.LastMessage = lastMessage.String
		}
		
		chats = append(chats, chat)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "Failed to process chats", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(chats)
}

func cleanupOldFiles() {
	logger.Info("Starting media files cleanup")
	
	files, err := afero.ReadDir(fs, cfg.Media.UploadPath)
	if err != nil {
		logger.Error("Failed to read upload directory", zap.Error(err))
		return
	}

	cutoff := time.Now().AddDate(0, 0, -cfg.Media.RetentionDays)
	deletedCount := 0
	totalSize := int64(0)

	for _, file := range files {
		if file.ModTime().Before(cutoff) {
			filePath := filepath.Join(cfg.Media.UploadPath, file.Name())
			if err := fs.Remove(filePath); err != nil {
				logger.Error("Failed to delete old file", 
					zap.String("file", file.Name()), 
					zap.Error(err))
			} else {
				deletedCount++
				totalSize += file.Size()
				logger.Debug("Deleted old file", 
					zap.String("file", file.Name()),
					zap.Int64("size", file.Size()),
					zap.Time("modified", file.ModTime()))
			}
		}
	}

	logger.Info("Cleanup completed", 
		zap.Int("files_deleted", deletedCount),
		zap.Int64("space_freed_bytes", totalSize),
		zap.Int("retention_days", cfg.Media.RetentionDays))
}

func generatePrivateChatID(user1ID, user2ID string) string {
	if user1ID < user2ID {
		return fmt.Sprintf("private_%s_%s", user1ID, user2ID)
	}
	return fmt.Sprintf("private_%s_%s", user2ID, user1ID)
}

func updateUserChats(userID, chatID string) {
	userChats.Lock()
	defer userChats.Unlock()
	
	if userChats.m[userID] == nil {
		userChats.m[userID] = make(map[string]bool)
	}
	userChats.m[userID][chatID] = true
}

func removeUserFromChats(userID, chatID string) {
	userChats.Lock()
	defer userChats.Unlock()
	
	if userChats.m[userID] != nil {
		delete(userChats.m[userID], chatID)
	}
}

func isUserOnline(userID string) bool {
	connections.RLock()
	defer connections.RUnlock()
	_, exists := connections.m[userID]
	return exists
}

func getUserByID(userID string) (*User, error) {
	users.RLock()
	cachedUser, exists := users.m[userID]
	users.RUnlock()

	if exists {
		cachedUser.IsOnline = isUserOnline(userID)
		return cachedUser, nil
	}

	user := &User{}
	var (
		lastSeenStr sql.NullString
		publicKey   sql.NullString
		avatarURL   sql.NullString
		phoneNumber sql.NullString
	)

	err := db.QueryRow(`
		SELECT id, username, phone_number, display_name, status, avatar_url, 
		       last_seen, public_key
		FROM users WHERE id = ?
	`, userID).Scan(
		&user.ID, &user.Username, &phoneNumber, &user.DisplayName, 
		&user.Status, &avatarURL, &lastSeenStr, &publicKey,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found: %s", userID)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	if phoneNumber.Valid {
		user.PhoneNumber = phoneNumber.String
	}
	if avatarURL.Valid {
		user.AvatarURL = avatarURL.String
	}
	if publicKey.Valid {
		user.PublicKey = publicKey.String
	}
	if lastSeenStr.Valid {
		if lastSeenTime, err := time.Parse("2006-01-02 15:04:05", lastSeenStr.String); err == nil {
			user.LastSeen = lastSeenTime
		}
	}

	user.IsOnline = isUserOnline(userID)

	users.Lock()
	users.m[userID] = user
	users.Unlock()

	logger.Debug("Loaded user from database", zap.String("user_id", userID))
	return user, nil
}

func createUser(username, password, displayName, phoneNumber string) (*User, error) {
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		return nil, errors.New("username and password are required")
	}

	if len(password) < 8 {
		return nil, errors.New("password must be at least 8 characters")
	}

	userID := generateID()
	
	passwordHash, err := HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &User{
		ID:          userID,
		Username:    strings.TrimSpace(username),
		PhoneNumber: strings.TrimSpace(phoneNumber),
		DisplayName: strings.TrimSpace(displayName),
		Status:      "Hey there! I am using Private Messenger",
		LastSeen:    time.Now(),
		IsOnline:    false,
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		`INSERT INTO users (id, username, phone_number, display_name, password_hash, last_seen) 
		 VALUES (?, ?, ?, ?, ?, ?)`,
		userID, user.Username, user.PhoneNumber, user.DisplayName, passwordHash, user.LastSeen,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			if strings.Contains(err.Error(), "username") {
				return nil, errors.New("username already exists")
			}
			if strings.Contains(err.Error(), "phone_number") {
				return nil, errors.New("phone number already registered")
			}
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	users.Lock()
	users.m[userID] = user
	users.Unlock()

	activeUsers.Inc()
	logger.Info("User created successfully", 
		zap.String("user_id", userID),
		zap.String("username", user.Username))

	return user, nil
}

func createGroupChat(creatorID, title, description string, memberIDs []string) (*Chat, error) {
	if strings.TrimSpace(title) == "" {
		return nil, errors.New("group title is required")
	}

	if len(memberIDs) > cfg.Limits.MaxGroupSize {
		return nil, fmt.Errorf("group size exceeds maximum limit of %d", cfg.Limits.MaxGroupSize)
	}

	allMembers := make(map[string]bool)
	allMembers[creatorID] = true
	for _, memberID := range memberIDs {
		allMembers[memberID] = true
	}

	for memberID := range allMembers {
		if _, err := getUserByID(memberID); err != nil {
			return nil, fmt.Errorf("invalid member ID: %s", memberID)
		}
	}

	chatID := generateID()
	chat := &Chat{
		ID:           chatID,
		Type:         ChatTypeGroup,
		Title:        strings.TrimSpace(title),
		Description:  strings.TrimSpace(description),
		CreatedBy:    creatorID,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		Admins:       []string{creatorID},
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		"INSERT INTO chats (id, type, title, description, created_by, last_activity) VALUES (?, ?, ?, ?, ?, ?)",
		chat.ID, chat.Type, chat.Title, chat.Description, chat.CreatedBy, chat.LastActivity,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create chat: %w", err)
	}

	for memberID := range allMembers {
		role := "member"
		if memberID == creatorID {
			role = "admin"
		}

		_, err = tx.Exec(
			"INSERT INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)",
			chat.ID, memberID, role,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to add member %s: %w", memberID, err)
		}

		chat.Members = append(chat.Members, ChatMember{
			UserID:   memberID,
			JoinedAt: time.Now(),
			Role:     role,
		})
		
		updateUserChats(memberID, chatID)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	chats.Lock()
	chats.m[chatID] = chat
	chats.Unlock()

	groupChatsGauge.Inc()
	
	logger.Info("Group chat created",
		zap.String("chat_id", chatID),
		zap.String("title", chat.Title),
		zap.Int("member_count", len(allMembers)))

	return chat, nil
}

func saveMessage(chatID, senderID, messageType, content, mediaURL string, replyTo *string, encrypted bool) (*Message, error) {
	if len(content) > cfg.Limits.MaxMessageLength {
		return nil, fmt.Errorf("message exceeds maximum length of %d characters", cfg.Limits.MaxMessageLength)
	}

	messageID := generateID()
	message := &Message{
		ID:        messageID,
		ChatID:    chatID,
		SenderID:  senderID,
		Type:      messageType,
		Content:   content,
		MediaURL:  mediaURL,
		Timestamp: time.Now(),
		ReplyTo:   replyTo,
		Encrypted: encrypted,
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		`INSERT INTO messages (id, chat_id, sender_id, type, content, media_url, reply_to, encrypted, timestamp) 
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		message.ID, message.ChatID, message.SenderID, message.Type, message.Content, 
		message.MediaURL, message.ReplyTo, message.Encrypted, message.Timestamp,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to save message: %w", err)
	}

	_, err = tx.Exec(
		"UPDATE chats SET last_activity = ? WHERE id = ?", 
		message.Timestamp, chatID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update chat activity: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	messagesProcessed.WithLabelValues(messageType, getChatType(chatID)).Inc()
	
	logger.Debug("Message saved",
		zap.String("message_id", messageID),
		zap.String("chat_id", chatID),
		zap.String("type", messageType))

	return message, nil
}

func getChatType(chatID string) string {
	chats.RLock()
	chat, exists := chats.m[chatID]
	chats.RUnlock()

	if exists {
		return chat.Type
	}

	var chatType string
	err := db.QueryRow("SELECT type FROM chats WHERE id = ?", chatID).Scan(&chatType)
	if err != nil {
		logger.Warn("Failed to get chat type", 
			zap.String("chat_id", chatID), 
			zap.Error(err))
		return ChatTypePrivate
	}

	return chatType
}

func endCall(callID, userID string) {
	activeCalls.Lock()
	call, exists := activeCalls.m[callID]
	activeCalls.Unlock()

	if !exists {
		logger.Warn("Call not found for ending", zap.String("call_id", callID))
		return
	}

	duration := int(time.Since(call.StartTime).Seconds())
	
	tx, err := db.Begin()
	if err != nil {
		logger.Error("Failed to begin transaction for call end", zap.Error(err))
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		"INSERT INTO calls (id, chat_id, call_type, initiator_id, duration, status, end_time) VALUES (?, ?, ?, ?, ?, ?, ?)",
		callID, call.ChatID, call.CallType, call.InitiatorID, duration, "completed", time.Now(),
	)
	if err != nil {
		logger.Error("Failed to save call record", 
			zap.String("call_id", callID),
			zap.Error(err))
	} else {
		if err := tx.Commit(); err != nil {
			logger.Error("Failed to commit call transaction", zap.Error(err))
		}
	}

	endMessage := map[string]interface{}{
		"type":      MessageTypeCallEnd,
		"call_id":   callID,
		"duration":  duration,
		"ended_by":  userID,
		"timestamp": time.Now().Unix(),
	}

	messageBytes, _ := json.Marshal(endMessage)
	broadcastToChat(call.ChatID, messageBytes, "")

	activeCalls.Lock()
	delete(activeCalls.m, callID)
	activeCalls.Unlock()

	callMetrics.WithLabelValues(call.CallType, "ended").Inc()
	
	logger.Info("Call ended",
		zap.String("call_id", callID),
		zap.String("chat_id", call.ChatID),
		zap.Int("duration_seconds", duration),
		zap.String("ended_by", userID))
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
		PhoneNumber string `json:"phone_number,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := createUser(req.Username, req.Password, req.DisplayName, req.PhoneNumber)
	if err != nil {
		logger.Warn("User registration failed",
			zap.String("username", req.Username),
			zap.Error(err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := NewToken(user.ID)
	if err != nil {
		logger.Error("Failed to generate JWT token",
			zap.String("user_id", user.ID),
			zap.Error(err))
		http.Error(w, "Failed to generate authentication token", http.StatusInternalServerError)
		return
	}

	userResponse := &User{
		ID:          user.ID,
		Username:    user.Username,
		DisplayName: user.DisplayName,
		Status:      user.Status,
		LastSeen:    user.LastSeen,
		IsOnline:    user.IsOnline,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user":  userResponse,
		"token": token,
	})

	logger.Info("User registered successfully",
		zap.String("user_id", user.ID),
		zap.String("username", user.Username),
		zap.Duration("duration", time.Since(start)))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var userID, passwordHash string
	err := db.QueryRow(
		"SELECT id, password_hash FROM users WHERE username = ?", 
		req.Username,
	).Scan(&userID, &passwordHash)
	
	if err != nil {
		logger.Warn("Login failed - user not found",
			zap.String("username", req.Username))
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !CheckPasswordHash(req.Password, passwordHash) {
		logger.Warn("Login failed - invalid password",
			zap.String("username", req.Username))
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	user, err := getUserByID(userID)
	if err != nil {
		logger.Error("Failed to get user after login",
			zap.String("user_id", userID),
			zap.Error(err))
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	token, err := NewToken(user.ID)
	if err != nil {
		logger.Error("Failed to generate token after login",
			zap.String("user_id", user.ID),
			zap.Error(err))
		http.Error(w, "Failed to generate authentication token", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("UPDATE users SET last_seen = ? WHERE id = ?", time.Now(), user.ID)
	if err != nil {
		logger.Warn("Failed to update user last seen",
			zap.String("user_id", user.ID),
			zap.Error(err))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user":  user,
		"token": token,
	})

	logger.Info("User logged in successfully",
		zap.String("user_id", user.ID),
		zap.String("username", user.Username),
		zap.Duration("duration", time.Since(start)))
}

func createGroupHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(string)

	var req struct {
		Title       string   `json:"title"`
		Description string   `json:"description,omitempty"`
		MemberIDs   []string `json:"member_ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	chat, err := createGroupChat(userID, req.Title, req.Description, req.MemberIDs)
	if err != nil {
		logger.Error("Failed to create group chat",
			zap.String("creator_id", userID),
			zap.Error(err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(chat)

	logger.Info("Group chat created via API",
		zap.String("chat_id", chat.ID),
		zap.String("title", chat.Title),
		zap.String("creator_id", userID))
}

type RateLimiter struct {
	requests map[string][]time.Time
	limit    int
	window   time.Duration
	mu       sync.Mutex
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (rl *RateLimiter) Allow(identifier string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	if _, exists := rl.requests[identifier]; !exists {
		rl.requests[identifier] = []time.Time{}
	}

	var valid []time.Time
	for _, t := range rl.requests[identifier] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	rl.requests[identifier] = valid

	if len(valid) < rl.limit {
		rl.requests[identifier] = append(rl.requests[identifier], now)
		return true
	}

	return false
}

var globalRateLimiter = NewRateLimiter(100, time.Second)

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identifier := r.RemoteAddr
		
		if !globalRateLimiter.Allow(identifier) {
			logger.Warn("Rate limit exceeded",
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("path", r.URL.Path))
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		
		next(w, r)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		userID, err := ValidateToken(token)
		if err != nil {
			logger.Warn("Invalid authentication token",
				zap.Error(err))
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if _, err := getUserByID(userID); err != nil {
			logger.Warn("User from token not found",
				zap.String("user_id", userID),
				zap.Error(err))
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "userID", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if err := db.Ping(); err != nil {
		http.Error(w, "Database unavailable", http.StatusServiceUnavailable)
		return
	}

	healthInfo := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
		"metrics": map[string]interface{}{
			"active_users": activeUsers,
			"websocket_connections": websocketConnections,
			"private_chats": privateChatsGauge,
			"group_chats": groupChatsGauge,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(healthInfo)
}

func timedHandler(endpoint, method string, handler http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		handler(w, r)
		duration := time.Since(start).Seconds()
		apiDuration.WithLabelValues(endpoint, method).Observe(duration)
	})
}

func getContactsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(string)

	rows, err := db.Query(`
		SELECT u.id, u.username, u.display_name, u.status, u.avatar_url, u.last_seen
		FROM contacts c
		INNER JOIN users u ON c.contact_id = u.id
		WHERE c.owner_id = ? AND c.is_blocked = FALSE
		ORDER BY u.display_name
	`, userID)
	if err != nil {
		http.Error(w, "Failed to fetch contacts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var contacts []User
	for rows.Next() {
		var contact User
		err := rows.Scan(&contact.ID, &contact.Username, &contact.DisplayName, &contact.Status, 
			&contact.AvatarURL, &contact.LastSeen)
		if err != nil {
			logger.Error("Failed to scan contact", zap.Error(err))
			continue
		}
		contact.IsOnline = isUserOnline(contact.ID)
		contacts = append(contacts, contact)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(contacts)
}

func addContactHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(string)

	var req struct {
		ContactID   string `json:"contact_id"`
		DisplayName string `json:"display_name,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var contactExists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?)", req.ContactID).Scan(&contactExists)
	if err != nil || !contactExists {
		http.Error(w, "Contact user not found", http.StatusNotFound)
		return
	}

	var alreadyAdded bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM contacts WHERE owner_id = ? AND contact_id = ?)", 
		userID, req.ContactID).Scan(&alreadyAdded)
	if err == nil && alreadyAdded {
		http.Error(w, "Contact already added", http.StatusConflict)
		return
	}

	contactID := generateID()
	_, err = db.Exec(
		"INSERT INTO contacts (id, owner_id, contact_id, display_name) VALUES (?, ?, ?, ?)",
		contactID, userID, req.ContactID, req.DisplayName,
	)
	if err != nil {
		http.Error(w, "Failed to add contact", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "contact_added", "contact_id": req.ContactID})
}

func getMessagesHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(string)
	chatID := r.URL.Query().Get("chat_id")
	limitStr := r.URL.Query().Get("limit")
	beforeStr := r.URL.Query().Get("before")

	if chatID == "" {
		http.Error(w, "chat_id is required", http.StatusBadRequest)
		return
	}

	var hasAccess bool
	err := db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?)",
		chatID, userID,
	).Scan(&hasAccess)
	if err != nil || !hasAccess {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	query := `
		SELECT m.id, m.chat_id, m.sender_id, m.type, m.content, m.media_url, 
		       m.timestamp, m.edited, m.edited_at, m.reply_to, m.encrypted,
		       u.display_name as sender_name
		FROM messages m
		INNER JOIN users u ON m.sender_id = u.id
		WHERE m.chat_id = ?
	`
	args := []interface{}{chatID}

	if beforeStr != "" {
		query += " AND m.timestamp < ?"
		args = append(args, beforeStr)
	}

	query += " ORDER BY m.timestamp DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		http.Error(w, "Failed to fetch messages", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []map[string]interface{}
	for rows.Next() {
		var (
			messageID, chatID, senderID, messageType, content, mediaURL string
			timestamp                                                   time.Time
			edited                                                      bool
			editedAt                                                    sql.NullTime
			replyTo                                                     sql.NullString
			encrypted                                                   bool
			senderName                                                  string
		)

		err := rows.Scan(&messageID, &chatID, &senderID, &messageType, &content, &mediaURL,
			&timestamp, &edited, &editedAt, &replyTo, &encrypted, &senderName)
		if err != nil {
			logger.Error("Failed to scan message", zap.Error(err))
			continue
		}

		message := map[string]interface{}{
			"id":         messageID,
			"chat_id":    chatID,
			"sender_id":  senderID,
			"sender_name": senderName,
			"type":       messageType,
			"content":    content,
			"media_url":  mediaURL,
			"timestamp":  timestamp,
			"edited":     edited,
			"encrypted":  encrypted,
		}

		if editedAt.Valid {
			message["edited_at"] = editedAt.Time
		}
		if replyTo.Valid {
			message["reply_to"] = replyTo.String
		}

		messages = append(messages, message)
	}

	for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
		messages[i], messages[j] = messages[j], messages[i]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func updateProfileHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(string)

	var req struct {
		DisplayName string `json:"display_name,omitempty"`
		Status      string `json:"status,omitempty"`
		AvatarURL   string `json:"avatar_url,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	updates := []string{}
	args := []interface{}{}

	if req.DisplayName != "" {
		updates = append(updates, "display_name = ?")
		args = append(args, req.DisplayName)
	}
	if req.Status != "" {
		updates = append(updates, "status = ?")
		args = append(args, req.Status)
	}
	if req.AvatarURL != "" {
		updates = append(updates, "avatar_url = ?")
		args = append(args, req.AvatarURL)
	}

	if len(updates) == 0 {
		http.Error(w, "No fields to update", http.StatusBadRequest)
		return
	}

	args = append(args, userID)
	query := fmt.Sprintf("UPDATE users SET %s WHERE id = ?", strings.Join(updates, ", "))

	_, err := db.Exec(query, args...)
	if err != nil {
		http.Error(w, "Failed to update profile", http.StatusInternalServerError)
		return
	}

	users.Lock()
	if user, exists := users.m[userID]; exists {
		if req.DisplayName != "" {
			user.DisplayName = req.DisplayName
		}
		if req.Status != "" {
			user.Status = req.Status
		}
		if req.AvatarURL != "" {
			user.AvatarURL = req.AvatarURL
		}
	}
	users.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "profile_updated"})
}

func webrtcHandler(w http.ResponseWriter, r *http.Request) {
	//userID := r.Context().Value("userID").(string)

	var signal struct {
		Type    string                 `json:"type"`
		CallID  string                 `json:"call_id,omitempty"`
		ChatID  string                 `json:"chat_id,omitempty"`
		Target  string                 `json:"target,omitempty"`
		Payload map[string]interface{} `json:"payload,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&signal); err != nil {
		http.Error(w, "Invalid signal data", http.StatusBadRequest)
		return
	}

	switch signal.Type {
	case "offer", "answer", "ice-candidate":
		connections.RLock()
		targetConn, exists := connections.m[signal.Target]
		connections.RUnlock()

		if exists {
			signalData, _ := json.Marshal(signal)
			err := targetConn.WriteMessage(websocket.TextMessage, signalData)
			if err != nil {
				logger.Warn("Failed to send WebRTC signal", 
					zap.String("target", signal.Target),
					zap.Error(err))
				http.Error(w, "Target user not connected", http.StatusBadRequest)
				return
			}
		} else {
			http.Error(w, "Target user not connected", http.StatusBadRequest)
			return
		}

	default:
		http.Error(w, "Unknown signal type", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "signal_sent"})
}

func main() {
	defer logger.Sync()

	logger.Info("Starting Private Messaging Server",
		zap.String("version", "1.0.0"))

	if err := initConfig(); err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}

	if err := initDB(); err != nil {
		logger.Fatal("Failed to initialize database", zap.Error(err))
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("Failed to close database", zap.Error(err))
		}
	}()

	if err := fs.MkdirAll(cfg.Media.UploadPath, 0755); err != nil {
		logger.Fatal("Failed to create upload directory", zap.Error(err))
	}

	c := cron.New()
	c.AddFunc("@daily", cleanupOldFiles)
	c.AddFunc("@hourly", func() {
		connections.RLock()
		connCount := len(connections.m)
		connections.RUnlock()
		
		users.RLock()
		userCount := len(users.m)
		users.RUnlock()
		
		chats.RLock()
		chatCount := len(chats.m)
		chats.RUnlock()

		logger.Info("System status report",
			zap.Int("active_connections", connCount),
			zap.Int("cached_users", userCount),
			zap.Int("cached_chats", chatCount))
	})
	c.Start()
	defer c.Stop()

	http.Handle("/ws", timedHandler("websocket", "GET", wsHandler))
	http.Handle("/api/register", timedHandler("register", "POST", rateLimitMiddleware(registerHandler)))
	http.Handle("/api/login", timedHandler("login", "POST", rateLimitMiddleware(loginHandler)))
	http.Handle("/api/profile", timedHandler("profile", "PUT", authMiddleware(updateProfileHandler)))
	http.Handle("/api/chats", timedHandler("chats", "GET", authMiddleware(getChatsHandler)))
	http.Handle("/api/messages", timedHandler("messages", "GET", authMiddleware(getMessagesHandler)))
	http.Handle("/api/contacts", timedHandler("contacts", "GET", authMiddleware(getContactsHandler)))
	http.Handle("/api/contacts/add", timedHandler("add_contact", "POST", authMiddleware(addContactHandler)))
	http.Handle("/api/groups", timedHandler("create_group", "POST", authMiddleware(createGroupHandler)))
	http.Handle("/api/upload", timedHandler("upload", "POST", authMiddleware(uploadMediaHandler)))
	http.Handle("/api/webrtc", timedHandler("webrtc", "POST", authMiddleware(webrtcHandler)))
	http.Handle("/media/", timedHandler("download", "GET", downloadMediaHandler))
	http.Handle("/health", timedHandler("health", "GET", healthHandler))
	http.Handle("/metrics", promhttp.Handler())

	http.Handle("/", http.FileServer(http.Dir("./static")))

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		},
	}

	// REMOVED the unused shutdownCtx variable that was causing the error
	// shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	// defer shutdownCancel()

	//shutdownCancel := context.CancelFunc(nil) // Placeholder if needed elsewhere

	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
		sig := <-sigint

		logger.Info("Received shutdown signal", 
			zap.String("signal", sig.String()),
			zap.String("service", "private-messaging-server"))
		
		// shutdownCancel() // This was unused

		logger.Info("Waiting for active connections to close...")
		
		time.Sleep(3 * time.Second)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("HTTP server shutdown failed", zap.Error(err))
		} else {
			logger.Info("HTTP server stopped gracefully")
		}
	}()

	logger.Info("Server starting", 
		zap.String("host", cfg.Server.Host), 
		zap.Int("port", cfg.Server.Port),
		zap.String("environment", "production"),
		zap.Strings("allowed_origins", cfg.Server.AllowedOrigins))

	if _, err := os.Stat("cert.pem"); os.IsNotExist(err) {
		logger.Fatal("TLS certificate (cert.pem) not found")
	}
	if _, err := os.Stat("key.pem"); os.IsNotExist(err) {
		logger.Fatal("TLS private key (key.pem) not found")
	}

	if err := srv.ListenAndServeTLS("cert.pem", "key.pem"); err != nil && err != http.ErrServerClosed {
		logger.Fatal("Server failed to start", zap.Error(err))
	}

	logger.Info("Server shutdown complete")
}
 


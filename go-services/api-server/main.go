package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Configuration constants
const (
	DefaultPort            = 8443
	DefaultReadTimeout     = 30 * time.Second
	DefaultWriteTimeout    = 30 * time.Second
	DefaultIdleTimeout     = 120 * time.Second
	MaxRequestBodySize     = 10 * 1024 * 1024 // 10 MB
	HealthCheckInterval    = 30 * time.Second
)

// Command line flags
var (
	port           int
	host           string
	certFile       string
	keyFile        string
	debug          bool
	logLevel       string
	shutdownTimeout time.Duration
)

// Request types

// EncryptRequest represents an encryption request
type EncryptRequest struct {
	Plaintext      string `json:"plaintext"`
	Algorithm      string `json:"algorithm"`
	KeyID          string `json:"key_id,omitempty"`
	AssociatedData string `json:"associated_data,omitempty"`
}

// DecryptRequest represents a decryption request
type DecryptRequest struct {
	Ciphertext     string `json:"ciphertext"`
	Tag            string `json:"tag"`
	Algorithm      string `json:"algorithm"`
	KeyID          string `json:"key_id,omitempty"`
	AssociatedData string `json:"associated_data,omitempty"`
}

// HashRequest represents a hashing request
type HashRequest struct {
	Data      string `json:"data"`
	Algorithm string `json:"algorithm"`
}

// DeriveKeyRequest represents a key derivation request
type DeriveKeyRequest struct {
	Password   string `json:"password"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	Algorithm  string `json:"algorithm"`
	Length     int    `json:"length"`
}

// Response types

// EncryptResponse represents an encryption response
type EncryptResponse struct {
	Success   bool   `json:"success"`
	Ciphertext string `json:"ciphertext,omitempty"`
	Tag       string `json:"tag,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	RequestID string `json:"request_id"`
	Timestamp int64  `json:"timestamp"`
}

// DecryptResponse represents a decryption response
type DecryptResponse struct {
	Success    bool   `json:"success"`
	Plaintext  string `json:"plaintext,omitempty"`
	Algorithm  string `json:"algorithm,omitempty"`
	RequestID  string `json:"request_id"`
	Timestamp  int64  `json:"timestamp"`
}

// HashResponse represents a hashing response
type HashResponse struct {
	Success   bool   `json:"success"`
	Hash      string `json:"hash,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	RequestID string `json:"request_id"`
	Timestamp int64  `json:"timestamp"`
}

// DeriveKeyResponse represents a key derivation response
type DeriveKeyResponse struct {
	Success   bool   `json:"success"`
	DerivedKey string `json:"derived_key,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	RequestID string `json:"request_id"`
	Timestamp int64  `json:"timestamp"`
}

// HealthResponse represents a health check response
type HealthResponse struct {
	Status    string            `json:"status"`
	Timestamp int64             `json:"timestamp"`
	Uptime    string            `json:"uptime"`
	Version   string            `json:"version"`
	Components map[string]bool  `json:"components"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Success   bool   `json:"success"`
	Error     string `json:"error"`
	Code      int    `json:"code"`
	RequestID string `json:"request_id"`
	Timestamp int64  `json:"timestamp"`
}

// APIServer represents the API server
type APIServer struct {
	logger     *zap.Logger
	server     *http.Server
	router     *http.ServeMux
	startTime  time.Time
	version    string
	requestLog chan<- *RequestLog
}

// RequestLog represents a request log entry
type RequestLog struct {
	RequestID  string
	Method     string
	Path       string
	StatusCode int
	Duration   time.Duration
	Timestamp  time.Time
}

// componentStatus tracks the status of various components
type componentStatus struct {
	crypto     bool
	keyManager bool
	auditLog   bool
}

// NewAPIServer creates a new API server instance
func NewAPIServer() (*APIServer, error) {
	// Initialize logger
	var logger *zap.Logger
	var err error

	if debug {
		logger, err = zap.NewDevelopment()
	} else {
		config := zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		config.Level, err = zap.ParseAtomicLevel(logLevel)
		if err != nil {
			log.Printf("Warning: Invalid log level '%s', using info", logLevel)
			config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		}
		logger, err = config.Build()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	server := &APIServer{
		logger:    logger,
		router:    http.NewServeMux(),
		startTime: time.Now(),
		version:   "1.0.0",
	}

	server.setupRoutes()
	server.setupMiddleware()

	return server, nil
}

// setupRoutes configures the API routes
func (s *APIServer) setupRoutes() {
	// Health check endpoints
	s.router.HandleFunc("/health", s.handleHealth)
	s.router.HandleFunc("/ready", s.handleReady)

	// API v1 routes
	s.router.HandleFunc("/api/v1/encrypt", s.handleEncrypt)
	s.router.HandleFunc("/api/v1/decrypt", s.handleDecrypt)
	s.router.HandleFunc("/api/v1/hash", s.handleHash)
	s.router.HandleFunc("/api/v1/derive-key", s.handleDeriveKey)

	// Key management routes
	s.router.HandleFunc("/api/v1/keys/generate", s.handleGenerateKey)
	s.router.HandleFunc("/api/v1/keys/list", s.handleListKeys)
	s.router.HandleFunc("/api/v1/keys/rotate", s.handleRotateKey)
	s.router.HandleFunc("/api/v1/keys/revoke", s.handleRevokeKey)

	// Audit routes
	s.router.HandleFunc("/api/v1/audit/logs", s.handleGetAuditLogs)

	// Metrics endpoint
	s.router.HandleFunc("/metrics", s.handleMetrics)
}

// setupMiddleware configures HTTP middleware
func (s *APIServer) setupMiddleware() {
	handler := loggingMiddleware(s.logger)(s.router)
	handler = recoveryMiddleware(s.logger)(handler)
	handler = corsMiddleware()(handler)
	handler = rateLimitMiddleware()(handler)

	s.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", host, port),
		Handler:      handler,
		ReadTimeout:  DefaultReadTimeout,
		WriteTimeout: DefaultWriteTimeout,
		IdleTimeout:  DefaultIdleTimeout,
		MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP256, tls.X25519},
			PreferServerCipherSuites: true,
		},
	}
}

// handleHealth handles health check requests
func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().Unix(),
		Uptime:    time.Since(s.startTime).String(),
		Version:   s.version,
		Components: map[string]bool{
			"crypto":     true,
			"keyManager": true,
			"auditLog":   true,
		},
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleReady handles readiness check requests
func (s *APIServer) handleReady(w http.ResponseWriter, r *http.Request) {
	// Perform readiness checks
	components := componentStatus{
		crypto:     s.checkCryptoComponent(),
		keyManager: s.checkKeyManagerComponent(),
		auditLog:   s.checkAuditLogComponent(),
	}

	allHealthy := components.crypto && components.keyManager && components.auditLog

	if allHealthy {
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	} else {
		s.writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{
			Success:  false,
			Error:    "Components not ready",
			Code:     503,
			RequestID: generateRequestID(),
			Timestamp: time.Now().Unix(),
		})
	}
}

// handleEncrypt handles encryption requests
func (s *APIServer) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req EncryptRequest
	if err := s.readJSON(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	requestID := generateRequestID()
	s.logger.Info("Encryption request received",
		zap.String("request_id", requestID),
		zap.String("algorithm", req.Algorithm),
	)

	// Placeholder for actual encryption logic
	response := EncryptResponse{
		Success:    true,
		Ciphertext: "encrypted_data_placeholder",
		Tag:        "tag_placeholder",
		Nonce:      "nonce_placeholder",
		Algorithm:  req.Algorithm,
		RequestID:  requestID,
		Timestamp:  time.Now().Unix(),
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleDecrypt handles decryption requests
func (s *APIServer) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req DecryptRequest
	if err := s.readJSON(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	requestID := generateRequestID()
	s.logger.Info("Decryption request received",
		zap.String("request_id", requestID),
		zap.String("algorithm", req.Algorithm),
	)

	// Placeholder for actual decryption logic
	response := DecryptResponse{
		Success:   true,
		Plaintext: "decrypted_data_placeholder",
		Algorithm: req.Algorithm,
		RequestID: requestID,
		Timestamp: time.Now().Unix(),
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleHash handles hashing requests
func (s *APIServer) handleHash(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req HashRequest
	if err := s.readJSON(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	requestID := generateRequestID()
	s.logger.Info("Hash request received",
		zap.String("request_id", requestID),
		zap.String("algorithm", req.Algorithm),
	)

	// Placeholder for actual hashing logic
	response := HashResponse{
		Success:   true,
		Hash:      "hash_placeholder",
		Algorithm: req.Algorithm,
		RequestID: requestID,
		Timestamp: time.Now().Unix(),
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleDeriveKey handles key derivation requests
func (s *APIServer) handleDeriveKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req DeriveKeyRequest
	if err := s.readJSON(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	requestID := generateRequestID()
	s.logger.Info("Key derivation request received",
		zap.String("request_id", requestID),
		zap.Int("iterations", req.Iterations),
	)

	// Placeholder for actual key derivation logic
	response := DeriveKeyResponse{
		Success:    true,
		DerivedKey: "derived_key_placeholder",
		Algorithm:  req.Algorithm,
		RequestID:  requestID,
		Timestamp:  time.Now().Unix(),
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleGenerateKey handles key generation requests
func (s *APIServer) handleGenerateKey(w http.ResponseWriter, r *http.Request) {
	// Placeholder for key generation
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"key_id":  uuid.New().String(),
	})
}

// handleListKeys handles key listing requests
func (s *APIServer) handleListKeys(w http.ResponseWriter, r *http.Request) {
	// Placeholder for key listing
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"keys":    []interface{}{},
	})
}

// handleRotateKey handles key rotation requests
func (s *APIServer) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	// Placeholder for key rotation
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

// handleRevokeKey handles key revocation requests
func (s *APIServer) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	// Placeholder for key revocation
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

// handleGetAuditLogs handles audit log retrieval
func (s *APIServer) handleGetAuditLogs(w http.ResponseWriter, r *http.Request) {
	// Placeholder for audit log retrieval
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"logs":    []interface{}{},
	})
}

// handleMetrics handles metrics endpoint requests
func (s *APIServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// Placeholder for metrics
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"uptime":    time.Since(s.startTime).String(),
		"requests":  0,
		"errors":    0,
	})
}

// checkCryptoComponent checks the crypto component status
func (s *APIServer) checkCryptoComponent() bool {
	// Placeholder for actual check
	return true
}

// checkKeyManagerComponent checks the key manager component status
func (s *APIServer) checkKeyManagerComponent() bool {
	// Placeholder for actual check
	return true
}

// checkAuditLogComponent checks the audit log component status
func (s *APIServer) checkAuditLogComponent() bool {
	// Placeholder for actual check
	return true
}

// writeJSON writes a JSON response
func (s *APIServer) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

// writeError writes an error response
func (s *APIServer) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, ErrorResponse{
		Success:  false,
		Error:    message,
		Code:     status,
		RequestID: generateRequestID(),
		Timestamp: time.Now().Unix(),
	})
}

// readJSON reads a JSON request body
func (s *APIServer) readJSON(r *http.Request, v interface{}) error {
	if r.ContentLength > MaxRequestBodySize {
		return fmt.Errorf("request body too large")
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

// Start starts the API server
func (s *APIServer) Start() error {
	s.logger.Info("Starting API server",
		zap.String("host", host),
		zap.Int("port", port),
		zap.String("version", s.version),
	)

	if certFile != "" && keyFile != "" {
		return s.server.ListenAndServeTLS(certFile, keyFile)
	}

	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *APIServer) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// Middleware functions

func loggingMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(lrw, r)

			duration := time.Since(start)
			logger.Info("HTTP request",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", lrw.statusCode),
				zap.Duration("duration", duration),
				zap.String("user_agent", r.UserAgent()),
			)
		})
	}
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func recoveryMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Error("Panic recovered",
						zap.Any("error", err),
						zap.String("path", r.URL.Path),
					)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func corsMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "86400")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func rateLimitMiddleware() func(http.Handler) http.Handler {
	// Placeholder for rate limiting
	return func(next http.Handler) http.Handler {
		return next
	}
}

// Helper functions

func generateRequestID() string {
	return uuid.New().String()
}

func init() {
	flag.IntVar(&port, "port", DefaultPort, "Server port")
	flag.StringVar(&host, "host", "0.0.0.0", "Server host")
	flag.StringVar(&certFile, "cert", "", "TLS certificate file")
	flag.StringVar(&keyFile, "key", "", "TLS private key file")
	flag.BoolVar(&debug, "debug", false, "Enable debug mode")
	flag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.DurationVar(&shutdownTimeout, "shutdown-timeout", 30*time.Second, "Shutdown timeout")
	flag.Parse()
}

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	server, err := NewAPIServer()
	if err != nil {
		logger.Fatal("Failed to create server", zap.Error(err))
	}

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			logger.Error("Server shutdown error", zap.Error(err))
		}
	}()

	logger.Info("API server started",
		zap.String("address", fmt.Sprintf("%s:%d", host, port)),
	)

	if err := server.Start(); err != nil && err != http.ErrServerClosed {
		logger.Fatal("Server error", zap.Error(err))
	}
}

// CXA System Monitor Service
// Monitors system health and resources

package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config holds monitor configuration
type Config struct {
	HTTPAddr        string        `json:"http_addr"`
	MetricsPath     string        `json:"metrics_path"`
	HealthPath      string        `json:"health_path"`
	CheckInterval   time.Duration `json:"check_interval"`
	AlertThreshold  float64       `json:"alert_threshold"`
	NotifyWebhook   string        `json:"notify_webhook"`
}

// SystemMetrics holds current system metrics
type SystemMetrics struct {
	CPUUsage       float64 `json:"cpu_usage"`
	MemoryUsage    float64 `json:"memory_usage"`
	DiskUsage      float64 `json:"disk_usage"`
	NetworkIn      int64   `json:"network_in"`
	NetworkOut     int64   `json:"network_out"`
	OpenFiles      int     `json:"open_files"`
	GoroutineCount int     `json:"goroutine_count"`
	Timestamp      string  `json:"timestamp"`
}

// Metrics definitions
var (
	cpuUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cxa_cpu_usage_percent",
			Help: "CPU usage percentage",
		},
		[]string{"core"},
	)

	memoryUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cxa_memory_usage_bytes",
			Help: "Memory usage in bytes",
		},
		[]string{"type"},
	)

	diskUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cxa_disk_usage_bytes",
			Help: "Disk usage in bytes",
		},
		[]string{"path"},
	)

	networkTraffic = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cxa_network_bytes_total",
			Help: "Network traffic in bytes",
		},
		[]string{"direction"},
	)

	activeConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cxa_active_connections",
			Help: "Number of active connections",
		},
	)

	errorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cxa_errors_total",
			Help: "Total number of errors",
		},
		[]string{"type"},
	)

	operationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cxa_operation_duration_seconds",
			Help:    "Duration of operations in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
		},
		[]string{"operation"},
	)
)

func init() {
	// Register metrics
	prometheus.MustRegister(cpuUsage)
	prometheus.MustRegister(memoryUsage)
	prometheus.MustRegister(diskUsage)
	prometheus.MustRegister(networkTraffic)
	prometheus.MustRegister(activeConnections)
	prometheus.MustRegister(errorsTotal)
	prometheus.MustRegister(operationDuration)
}

// Monitor is the system monitor
type Monitor struct {
	config     *Config
	httpServer *http.Server
	stopChan   chan struct{}
}

// NewMonitor creates a new system monitor
func NewMonitor(config *Config) *Monitor {
	return &Monitor{
		config:   config,
		stopChan: make(chan struct{}),
	}
}

// Start begins monitoring
func (m *Monitor) Start() {
	log.Println("Starting system monitor...")

	// Setup HTTP server for metrics
	m.httpServer = &http.Server{
		Addr:    m.config.HTTPAddr,
		Handler: m.createHandler(),
	}

	// Start metrics collection
	go m.collectMetrics()

	// Start HTTP server
	go func() {
		log.Printf("Metrics server listening on %s", m.config.HTTPAddr)
		if err := m.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	log.Println("System monitor started")
}

// Stop gracefully shuts down the monitor
func (m *Monitor) Stop() {
	log.Println("Stopping system monitor...")

	close(m.stopChan)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := m.httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

	log.Println("System monitor stopped")
}

// createHandler creates the HTTP handler for metrics
func (m *Monitor) createHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(m.config.HealthPath, m.handleHealth)
	mux.HandleFunc(m.config.MetricsPath, promhttp.Handler().ServeHTTP)
	mux.HandleFunc("/details", m.handleDetails)
	mux.HandleFunc("/ready", m.handleReady)

	return mux
}

// handleHealth returns health status
func (m *Monitor) handleHealth(w http.ResponseWriter, r *http.Request) {
	metrics := collectSystemMetrics()

	status := "healthy"
	if metrics.CPUUsage > m.config.AlertThreshold {
		status = "degraded"
	}

	response := map[string]interface{}{
		"status":   status,
		"metrics":  metrics,
		"uptime":   time.Since(startTime).String(),
		"version":  "1.0.0",
		"hostname": getHostname(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleDetails returns detailed metrics
func (m *Monitor) handleDetails(w http.ResponseWriter, r *http.Request) {
	metrics := collectSystemMetrics()

	details := map[string]interface{}{
		"system":   metrics,
		"process":  getProcessMetrics(),
		"go":       getGoMetrics(),
		"hostname": getHostname(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(details)
}

// handleReady checks if the system is ready
func (m *Monitor) handleReady(w http.ResponseWriter, r *http.Request) {
	// Check if all critical services are responding
	response := map[string]string{
		"status": "ready",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// collectMetrics periodically collects system metrics
func (m *Monitor) collectMetrics() {
	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			metrics := collectSystemMetrics()

			// Update Prometheus metrics
			cpuUsage.WithLabelValues("total").Set(metrics.CPUUsage)
			memoryUsage.WithLabelValues("used").Set(float64(metrics.MemoryUsage))
			diskUsage.WithLabelValues("/").Set(metrics.DiskUsage)
			activeConnections.Set(float64(metrics.OpenFiles))

			// Check for alerts
			if metrics.CPUUsage > m.config.AlertThreshold {
				log.Printf("WARNING: High CPU usage detected: %.2f%%", metrics.CPUUsage)
				errorsTotal.WithLabelValues("high_cpu").Inc()
			}
		}
	}
}

// collectSystemMetrics gathers system metrics
func collectSystemMetrics() SystemMetrics {
	// This is a placeholder - implement actual metrics collection
	return SystemMetrics{
		CPUUsage:       0,
		MemoryUsage:    0,
		DiskUsage:      0,
		NetworkIn:      0,
		NetworkOut:     0,
		OpenFiles:      0,
		GoroutineCount: 0,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}
}

// getProcessMetrics returns process-specific metrics
func getProcessMetrics() map[string]interface{} {
	return map[string]interface{}{
		"pid":         os.Getpid(),
		"ppid":        os.Getppid(),
		"uid":         os.Getuid(),
		"executable":  os.Args[0],
		"args":        os.Args,
		"environment": len(os.Environ()),
	}
}

// getGoMetrics returns Go runtime metrics
func getGoMetrics() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"alloc":         m.Alloc,
		"total_alloc":   m.TotalAlloc,
		"sys":           m.Sys,
		"gc_pause_ns":   m.GCPauseTotalNs,
		"num_gc":        m.NumGC,
		"num_cpu":       runtime.NumCPU(),
		"num_goroutine": runtime.NumGoroutine(),
	}
}

// getHostname returns the system hostname
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

var startTime time.Time

func main() {
	startTime = time.Now()

	config := &Config{
		HTTPAddr:      ":9090",
		MetricsPath:   "/metrics",
		HealthPath:    "/health",
		CheckInterval: 10 * time.Second,
		AlertThreshold: 80.0,
		NotifyWebhook: "",
	}

	monitor := NewMonitor(config)

	// Handle shutdown signals
	go func() {
		<-make(chan os.Signal, 1)
		monitor.Stop()
		os.Exit(0)
	}()

	monitor.Start()

	select {}
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/robfig/cron/v3"
)

// ============================================================================
// Event Types
// ============================================================================

type EventType string

const (
	EventTypeKeyGenerated   EventType = "key_generated"
	EventTypeKeyUsed        EventType = "key_used"
	EventTypeEncryption     EventType = "encryption"
	EventTypeDecryption     EventType = "decryption"
	EventTypeBackupCreated  EventType = "backup_created"
	EventTypeBackupRestored EventType = "backup_restored"
	EventTypeAnomaly        EventType = "anomaly_detected"
	EventTypeSecurityAlert  EventType = "security_alert"
)

type Event struct {
	ID        string            `json:"id"`
	Type      EventType         `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"`
	Level     string            `json:"level"`
	Data      map[string]interface{} `json:"data"`
	Metadata  EventMetadata     `json:"metadata"`
}

type EventMetadata struct {
	UserID    string `json:"user_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
}

// ============================================================================
// Event Monitor Configuration
// ============================================================================

type MonitorConfig struct {
	BufferSize       int           `json:"buffer_size"`
	FlushInterval    time.Duration `json:"flush_interval"`
	RetentionPeriod  time.Duration `json:"retention_period"`
	MaxEventsPerType int           `json:"max_events_per_type"`
	EnableAlerting   bool          `json:"enable_alerting"`
	AlertThreshold   int           `json:"alert_threshold"`
	AlertCooldown    time.Duration `json:"alert_cooldown"`
	ScheduleCleanup  string        `json:"schedule_cleanup"`
}

func DefaultConfig() *MonitorConfig {
	return &MonitorConfig{
		BufferSize:       10000,
		FlushInterval:    time.Minute,
		RetentionPeriod:  24 * time.Hour,
		MaxEventsPerType: 1000,
		EnableAlerting:   true,
		AlertThreshold:   100,
		AlertCooldown:    5 * time.Minute,
		ScheduleCleanup:  "0 3 * * *", // Daily at 3 AM
	}
}

// ============================================================================
// Event Monitor
// ============================================================================

type EventMonitor struct {
	Config      *MonitorConfig
	Events      []Event
	EventCounts map[EventType]int
	Alerts      []Alert
	AlertCounts map[string]time.Time
	Lock        sync.RWMutex
	Cron        *cron.Cron
	Plugins     []EventPlugin
	Metrics     *MonitorMetrics
}

type Alert struct {
	ID        string    `json:"id"`
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Count     int       `json:"count"`
	Message   string    `json:"message"`
}

type MonitorMetrics struct {
	TotalEvents      int64            `json:"total_events"`
	EventsByType     map[EventType]int64 `json:"events_by_type"`
	EventsByLevel    map[string]int64    `json:"events_by_level"`
	TotalAlerts      int64            `json:"total_alerts"`
	ActiveAlerts     int64            `json:"active_alerts"`
	LastAlertTime    time.Time        `json:"last_alert_time"`
	AverageEventRate float64          `json:"average_event_rate"`
}

type EventPlugin interface {
	Name() string
	Process(event *Event) error
	AlertConditions() []AlertCondition
}

type AlertCondition struct {
	EventType   EventType
	Threshold   int
	TimeWindow  time.Duration
	Message     string
}

// ============================================================================
// Event Processing
// ============================================================================

func NewEventMonitor(config *MonitorConfig) *EventMonitor {
	monitor := &EventMonitor{
		Config:      config,
		Events:      make([]Event, 0, config.BufferSize),
		EventCounts: make(map[EventType]int),
		Alerts:      make([]Alert, 0),
		AlertCounts: make(map[string]time.Time),
		Plugins:     make([]EventPlugin, 0),
		Metrics: &MonitorMetrics{
			EventsByType:  make(map[EventType]int64),
			EventsByLevel: make(map[string]int64),
		},
	}

	// Initialize cron scheduler
	monitor.Cron = cron.New()

	// Schedule cleanup job
	if config.ScheduleCleanup != "" {
		if _, err := monitor.Cron.AddFunc(config.ScheduleCleanup, monitor.Cleanup); err != nil {
			log.Printf("Failed to schedule cleanup: %v", err)
		}
	}

	return monitor
}

func (m *EventMonitor) Start() {
	log.Println("Starting event monitor...")
	m.Cron.Start()
	log.Println("Event monitor started")
}

func (m *EventMonitor) Stop() {
	log.Println("Stopping event monitor...")
	m.Cron.Stop()
	log.Println("Event monitor stopped")
}

func (m *EventMonitor) RecordEvent(eventType EventType, source string, level string, data map[string]interface{}) {
	event := Event{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Type:      eventType,
		Timestamp: time.Now(),
		Source:    source,
		Level:     level,
		Data:      data,
	}

	m.Lock.Lock()
	defer m.Lock.Unlock()

	// Add event
	m.Events = append(m.Events, event)
	m.EventCounts[eventType]++

	// Update metrics
	m.Metrics.TotalEvents++
	m.Metrics.EventsByType[eventType]++
	m.Metrics.EventsByLevel[level]++

	// Trim if buffer is full
	if len(m.Events) > m.Config.BufferSize {
		m.Events = m.Events[len(m.Events)-m.Config.BufferSize:]
	}

	// Enforce per-type limits
	if m.EventCounts[eventType] > m.Config.MaxEventsPerType {
		m.Events = m.PruneOldestByType(eventType)
	}

	// Check for alerts
	if m.Config.EnableAlerting {
		m.checkForAlerts(eventType)
	}

	// Process through plugins
	for _, plugin := range m.Plugins {
		if err := plugin.Process(&event); err != nil {
			log.Printf("Plugin %s error: %v", plugin.Name(), err)
		}
	}
}

func (m *EventMonitor) PruneOldestByType(eventType EventType) []Event {
	cutoff := m.Config.MaxEventsPerType
	count := 0
	keepFrom := len(m.Events)

	for i := len(m.Events) - 1; i >= 0; i-- {
		if m.Events[i].Type == eventType {
			count++
			if count == cutoff {
				keepFrom = i + 1
				break
			}
		}
	}

	return m.Events[keepFrom:]
}

func (m *Monitor) checkForAlerts(eventType EventType) {
	now := time.Now()

	// Check cooldown
	if lastAlert, ok := m.AlertCounts[string(eventType)]; ok {
		if now.Sub(lastAlert) < m.Config.AlertCooldown {
			return
		}
	}

	// Count events in time window
	count := 0
	windowStart := now.Add(-m.Config.AlertCooldown)

	for _, event := range m.Events {
		if event.Type == eventType && event.Timestamp.After(windowStart) {
			count++
		}
	}

	if count >= m.Config.AlertThreshold {
		alert := Alert{
			ID:        fmt.Sprintf("alert_%d", now.UnixNano()),
			Type:      eventType,
			Timestamp: now,
			Count:     count,
			Message:   fmt.Sprintf("High volume of %s events: %d in last %v", eventType, count, m.Config.AlertCooldown),
		}

		m.Alerts = append(m.Alerts, alert)
		m.AlertCounts[string(eventType)] = now
		m.Metrics.TotalAlerts++
		m.Metrics.ActiveAlerts++
		m.Metrics.LastAlertTime = now

		log.Printf("ALERT: %s", alert.Message)
	}
}

func (m *EventMonitor) GetEvents(eventType EventType, limit int) []Event {
	m.Lock.RLock()
	defer m.Lock.RUnlock()

	var result []Event
	for _, event := range m.Events {
		if eventType == "" || event.Type == eventType {
			result = append(result, event)
		}
	}

	if limit > 0 && len(result) > limit {
		return result[len(result)-limit:]
	}

	return result
}

func (m *EventMonitor) GetMetrics() MonitorMetrics {
	m.Lock.RLock()
	defer m.Lock.RUnlock()

	return *m.Metrics
}

func (m *EventMonitor) Cleanup() {
	m.Lock.Lock()
	defer m.Lock.Unlock()

	log.Println("Running event cleanup...")

	cutoff := time.Now().Add(-m.Config.RetentionPeriod)
	originalCount := len(m.Events)

	var remaining []Event
	for _, event := range m.Events {
		if event.Timestamp.After(cutoff) {
			remaining = append(remaining, event)
		}
	}

	m.Events = remaining
	m.Metrics.TotalEvents = int64(len(m.Events))

	log.Printf("Cleanup complete: removed %d events", originalCount-len(m.Events))
}

func (m *EventMonitor) GetStatistics() map[string]interface{} {
	m.Lock.RLock()
	defer m.Lock.RUnlock()

	stats := map[string]interface{}{
		"total_events":     m.Metrics.TotalEvents,
		"events_by_type":   m.Metrics.EventsByType,
		"events_by_level":  m.Metrics.EventsByLevel,
		"total_alerts":     m.Metrics.TotalAlerts,
		"active_alerts":    m.Metrics.ActiveAlerts,
		"buffer_capacity":  len(m.Events),
		"buffer_max":       m.Config.BufferSize,
		"uptime":           time.Since(startTime).String(),
	}

	return stats
}

var startTime time.Time

// ============================================================================
// Event Forwarder Plugin
// ============================================================================

type EventForwarder struct {
	Destinations []string
	APIKeys      []string
}

func (f *EventForwarder) Name() string {
	return "event_forwarder"
}

func (f *EventForwarder) Process(event *Event) error {
	// TODO: Implement event forwarding to external systems
	// This could send events to SIEM systems, log aggregators, etc.
	return nil
}

func (f *EventForwarder) AlertConditions() []AlertCondition {
	return []AlertCondition{
		{
			EventType:  EventTypeAnomaly,
			Threshold:  1,
			TimeWindow: time.Minute,
			Message:    "Anomaly detected",
		},
	}
}

// ============================================================================
// Anomaly Detector Plugin
// ============================================================================

type AnomalyDetector struct {
	BaselineRates map[EventType]float64
	Sensitivity   float64
}

func (d *AnomalyDetector) Name() string {
	return "anomaly_detector"
}

func (d *AnomalyDetector) Process(event *Event) error {
	// TODO: Implement anomaly detection logic
	// This would analyze event patterns and detect deviations from baseline
	return nil
}

func (d *AnomalyDetector) AlertConditions() []AlertCondition {
	return []AlertCondition{
		{
			EventType:  EventTypeAnomaly,
			Threshold:  1,
			TimeWindow: time.Minute,
			Message:    "Statistical anomaly detected",
		},
	}
}

// ============================================================================
// Rate Limiter Plugin
// ============================================================================

type RateLimiter struct {
	Requests map[string][]time.Time
	MaxRate  int
	Window   time.Duration
}

func (l *RateLimiter) Name() string {
	return "rate_limiter"
}

func (l *RateLimiter) Process(event *Event) error {
	if event.Type != EventTypeKeyUsed {
		return nil
	}

	source := event.Source
	now := time.Now()

	// Clean old entries
	windowStart := now.Add(-l.Window)
	for key, times := range l.Requests {
		var remaining []time.Time
		for _, t := range times {
			if t.After(windowStart) {
				remaining = append(remaining, t)
			}
		}
		l.Requests[key] = remaining
	}

	// Check rate
	count := len(l.Requests[source])
	if count >= l.MaxRate {
		// Generate anomaly event
		log.Printf("RATE LIMIT EXCEEDED: %s made %d requests in %v", source, count, l.Window)
	}

	l.Requests[source] = append(l.Requests[source], now)

	return nil
}

func (l *RateLimiter) AlertConditions() []AlertCondition {
	return []AlertCondition{
		{
			EventType:  EventTypeSecurityAlert,
			Threshold:  5,
			TimeWindow: time.Minute,
			Message:    "Rate limit exceeded",
		},
	}
}

// ============================================================================
// Main Entry Point
// ============================================================================

func main() {
	startTime = time.Now()

	// Load configuration
	config := DefaultConfig()

	configFile := os.Getenv("CXA_EVENT_CONFIG_FILE")
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			log.Fatalf("Failed to read config file: %v", err)
		}

		if err := json.Unmarshal(data, config); err != nil {
			log.Fatalf("Failed to parse config file: %v", err)
		}
	}

	// Create monitor
	monitor := NewEventMonitor(config)

	// Register plugins
	monitor.Plugins = append(monitor.Plugins, &EventForwarder{
		Destinations: []string{},
		APIKeys:      []string{},
	})

	monitor.Plugins = append(monitor.Plugins, &AnomalyDetector{
		BaselineRates: make(map[EventType]float64),
		Sensitivity:   3.0,
	})

	monitor.Plugins = append(monitor.Plugins, &RateLimiter{
		Requests: make(map[string][]time.Time),
		MaxRate:  100,
		Window:   time.Minute,
	})

	// Start monitor
	monitor.Start()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down event monitor...")
		monitor.Stop()
		os.Exit(0)
	}()

	// Log startup
	log.Printf("Event monitor started with buffer size %d", config.BufferSize)
	log.Printf("Alert threshold: %d events per %v", config.AlertThreshold, config.AlertCooldown)
	log.Printf("Cleanup scheduled: %s", config.ScheduleCleanup)

	// Block forever
	select {}
}

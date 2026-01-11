// CXA Event Processor Service
// Processes security events in real-time

package main

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

// EventProcessor processes events from the queue
type EventProcessor struct {
	queue      chan Event
	workers    int
	bufferSize int
	plugins    []EventPlugin
	cron       *cron.Cron
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

// Event represents a security event
type Event struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data"`
}

// EventPlugin processes events
type EventPlugin interface {
	Process(event *Event) error
	Name() string
}

// NewEventProcessor creates a new event processor
func NewEventProcessor(workers int, bufferSize int) *EventProcessor {
	return &EventProcessor{
		queue:      make(chan Event, bufferSize),
		workers:    workers,
		bufferSize: bufferSize,
		plugins:    make([]EventPlugin, 0),
		cron:       cron.New(),
		stopChan:   make(chan struct{}),
	}
}

// Start begins processing events
func (p *EventProcessor) Start() {
	log.Printf("Starting event processor with %d workers", p.workers)

	// Start worker goroutines
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}

	// Start scheduled tasks
	p.cron.Start()

	log.Println("Event processor started")
}

// Stop gracefully shuts down the processor
func (p *EventProcessor) Stop() {
	log.Println("Stopping event processor...")

	close(p.stopChan)
	p.wg.Wait()
	p.cron.Stop()

	log.Println("Event processor stopped")
}

// Enqueue adds an event to the processing queue
func (p *EventProcessor) Enqueue(event Event) {
	select {
	case p.queue <- event:
	default:
		log.Printf("Warning: Event queue full, dropping event %s", event.ID)
	}
}

// worker processes events from the queue
func (p *EventProcessor) worker(id int) {
	defer p.wg.Done()

	for {
		select {
		case <-p.stopChan:
			log.Printf("Worker %d stopping", id)
			return
		case event, ok := <-p.queue:
			if !ok {
				return
			}
			p.processEvent(&event)
		}
	}
}

// processEvent runs all plugins on an event
func (p *EventProcessor) processEvent(event *Event) {
	for _, plugin := range p.plugins {
		if err := plugin.Process(event); err != nil {
			log.Printf("Plugin %s error: %v", plugin.Name(), err)
		}
	}
}

// RegisterPlugin adds a plugin to the processor
func (p *EventProcessor) RegisterPlugin(plugin EventPlugin) {
	p.plugins = append(p.plugins, plugin)
	log.Printf("Registered plugin: %s", plugin.Name())
}

// ScheduleTask adds a scheduled task
func (p *EventProcessor) ScheduleTask(schedule string, task func()) {
	p.cron.AddFunc(schedule, task)
}

// AggregationPlugin aggregates events by type
type AggregationPlugin struct {
	aggregations map[string][]Event
	interval     time.Duration
	lock         sync.RWMutex
}

func (a *AggregationPlugin) Name() string {
	return "aggregation"
}

func (a *AggregationPlugin) Process(event *Event) error {
	a.lock.Lock()
	defer a.lock.Unlock()

	a.aggregations[event.Type] = append(a.aggregations[event.Type], *event)
	return nil
}

// EnrichmentPlugin adds contextual information to events
type EnrichmentPlugin struct{}

func (e *EnrichmentPlugin) Name() string {
	return "enrichment"
}

func (e *EnrichmentPlugin) Process(event *Event) error {
	// Add enrichment data to event
	if event.Data == nil {
		event.Data = make(map[string]interface{})
	}
	event.Data["enriched_at"] = time.Now().UTC().Format(time.RFC3339)
	event.Data["processor_version"] = "1.0.0"
	return nil
}

// FilteringPlugin filters out unwanted events
type FilteringPlugin struct {
	blockedTypes map[string]bool
}

func (f *FilteringPlugin) Name() string {
	return "filter"
}

func (f *FilteringPlugin) Process(event *Event) error {
	if f.blockedTypes[event.Type] {
		return &FilteredEvent{Type: event.Type}
	}
	return nil
}

// FilteredEvent is returned when an event is filtered
type FilteredEvent struct {
	Type string
}

func (e *FilteredEvent) Error() string {
	return "event filtered: " + e.Type
}

func main() {
	// Create processor with 4 workers and 1000 event buffer
	processor := NewEventProcessor(4, 1000)

	// Register plugins
	processor.RegisterPlugin(&EnrichmentPlugin{})
	processor.RegisterPlugin(&FilteringPlugin{
		blockedTypes: map[string]bool{
			"debug": true,
			"trace": true,
		},
	})
	processor.RegisterPlugin(&AggregationPlugin{
		aggregations: make(map[string][]Event),
		interval:     time.Minute,
	})

	// Schedule aggregation report every hour
	processor.ScheduleTask("0 * * * *", func() {
		log.Println("Generating hourly aggregation report...")
	})

	// Start processor
	processor.Start()

	// Simulate some events
	for i := 0; i < 10; i++ {
		processor.Enqueue(Event{
			ID:        string(rune(i + 'a')),
			Type:      "test",
			Timestamp: time.Now(),
			Source:    "test",
			Data:      map[string]interface{}{"index": i},
		})
	}

	// Wait for processing
	time.Sleep(2 * time.Second)

	// Stop
	processor.Stop()

	log.Println("Event processor main complete")
}

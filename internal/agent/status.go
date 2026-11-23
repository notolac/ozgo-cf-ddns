package agent

import (
	"sync"
	"time"

	"github.com/notolac/ozgo-cf-ddns/internal/config"
)

// State is the sync state of a record.
type State string

const (
	StatePending State = "pending" // not checked yet
	StateOK      State = "ok"      // Cloudflare matches the desired value
	StateError   State = "error"   // last check failed
)

// RecordStatus is what the web interface shows for one record. It never
// contains credentials.
type RecordStatus struct {
	Name               string    `json:"name"`
	FQDN               string    `json:"fqdn"`
	Zone               string    `json:"zone"`
	Type               string    `json:"type"`
	Proxied            bool      `json:"proxied"`
	Source             string    `json:"source"`
	State              State     `json:"state"`
	DesiredIP          string    `json:"desired_ip,omitempty"`
	CloudflareIP       string    `json:"cloudflare_ip,omitempty"`
	CloudflareProxied  *bool     `json:"cloudflare_proxied,omitempty"`
	CloudflareModified time.Time `json:"cloudflare_modified,omitzero"`
	LastCheck          time.Time `json:"last_check,omitzero"`
	LastSuccess        time.Time `json:"last_success,omitzero"`
	LastChange         time.Time `json:"last_change,omitzero"`
	LastError          string    `json:"last_error,omitempty"`
	LastErrorAt        time.Time `json:"last_error_at,omitzero"`
	Failures           int       `json:"consecutive_failures"`
}

// Snapshot is a consistent copy of the agent state.
type Snapshot struct {
	Version    string         `json:"version"`
	Started    time.Time      `json:"started"`
	Schedule   string         `json:"schedule"`
	RoundStart time.Time      `json:"last_round_start,omitzero"`
	RoundEnd   time.Time      `json:"last_round_end,omitzero"`
	NextRound  time.Time      `json:"next_round,omitzero"`
	Healthy    bool           `json:"healthy"`
	OK         int            `json:"ok"`
	Errors     int            `json:"errors"`
	Pending    int            `json:"pending"`
	Records    []RecordStatus `json:"records"`
}

// Status holds the live state shared between the agent and the web server.
type Status struct {
	mu      sync.RWMutex
	snap    Snapshot
	changed chan struct{}
}

func newStatus(version string, started time.Time, cfg *config.Config) *Status {
	s := &Status{
		snap:    Snapshot{Version: version, Started: started, Schedule: cfg.Schedule.String()},
		changed: make(chan struct{}, 1),
	}
	for _, r := range cfg.Records {
		s.snap.Records = append(s.snap.Records, RecordStatus{
			Name: r.Name, FQDN: r.FQDN(), Zone: r.Zone, Type: r.Type,
			Proxied: r.Proxied, Source: string(r.Source), State: StatePending,
		})
	}
	s.recount()
	return s
}

// Snapshot returns a copy of the current state.
func (s *Status) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.snap
	out.Records = make([]RecordStatus, len(s.snap.Records))
	copy(out.Records, s.snap.Records)
	return out
}

func (s *Status) update(i int, fn func(*RecordStatus)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.snap.Records[i])
	s.recount()
}

func (s *Status) round(start, end, next time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !start.IsZero() {
		s.snap.RoundStart = start
	}
	if !end.IsZero() {
		s.snap.RoundEnd = end
	}
	s.snap.NextRound = next
	s.recount()
	select {
	case s.changed <- struct{}{}:
	default: // a notification is already pending
	}
}

// Changes receives a value when a round starts or ends. Notifications are coalesced:
// a slow reader sees one pending signal, never a backlog.
func (s *Status) Changes() <-chan struct{} { return s.changed }

// recount must be called with mu held.
func (s *Status) recount() {
	s.snap.OK, s.snap.Errors, s.snap.Pending = 0, 0, 0
	for _, r := range s.snap.Records {
		switch r.State {
		case StateOK:
			s.snap.OK++
		case StateError:
			s.snap.Errors++
		default:
			s.snap.Pending++
		}
	}
	s.snap.Healthy = !s.snap.RoundEnd.IsZero() && s.snap.Errors == 0 && s.snap.Pending == 0
}

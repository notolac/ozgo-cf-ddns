// Package hub lets several ozgo-cf-ddns containers share one status page.
//
// The main container keeps a Store and serves Handler on POST /api/sync.
// Sidecars run a Reporter that sends their status there after every round and
// at a fixed interval. Both sides share SYNC_KEY. The key itself never travels:
// each report is signed with HMAC-SHA256 over a timestamp and the body.
//
//	X-Ozgo-Timestamp: <unix milliseconds>
//	X-Ozgo-Signature: v1=<hex HMAC-SHA256(key, timestamp + "\n" + body)>
//
// The main container rejects bad signatures, timestamps more than MaxSkew
// away from its clock, and timestamps not newer than the last accepted report
// of the same instance (replays).
package hub

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/notolac/ozgo-cf-ddns/internal/agent"
	"github.com/notolac/ozgo-cf-ddns/internal/config"
)

const (
	// Path is where the main container accepts reports.
	Path = "/api/sync"

	HeaderTimestamp = "X-Ozgo-Timestamp"
	HeaderSignature = "X-Ozgo-Signature"

	// MaxSkew is the largest accepted difference between clocks.
	MaxSkew = 5 * time.Minute
	// MaxBody is the largest accepted report.
	MaxBody = 2 << 20
	// MaxRecords is the largest number of records in one report.
	MaxRecords = 1000
	// MaxInstances is the largest number of sidecars one main container tracks.
	MaxInstances = 32
	// StaleAfter marks a sidecar as stale when it has not reported for this long.
	StaleAfter = 2 * time.Minute
	// ForgetAfter drops a sidecar that has not reported for this long, so a
	// renamed sidecar does not stay on the page forever.
	ForgetAfter = 24 * time.Hour
)

var versionRE = regexp.MustCompile(`^[0-9A-Za-z.+_-]{0,64}$`)

// Report is the body a sidecar sends.
type Report struct {
	Instance string         `json:"instance"`
	Status   agent.Snapshot `json:"status"`
}

// Sign returns the X-Ozgo-Signature value for a report.
func Sign(key []byte, ts int64, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(strconv.FormatInt(ts, 10)))
	m.Write([]byte{'\n'})
	m.Write(body)
	return "v1=" + hex.EncodeToString(m.Sum(nil))
}

// Verify checks a signature in constant time.
func Verify(key []byte, ts int64, body []byte, signature string) bool {
	return hmac.Equal([]byte(Sign(key, ts, body)), []byte(signature))
}

// Remote is the last known state of one sidecar.
type Remote struct {
	Instance string         `json:"instance"`
	Received time.Time      `json:"last_report"`
	Stale    bool           `json:"stale"`
	Status   agent.Snapshot `json:"status"`
}

type entry struct {
	remote Remote
	lastTS int64
}

// Store keeps the reports of the sidecars in memory.
type Store struct {
	local string // instance name of the main container
	now   func() time.Time

	mu      sync.Mutex
	entries map[string]*entry
}

// NewStore creates a store for the main container named local.
func NewStore(local string, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{local: local, now: now, entries: map[string]*entry{}}
}

// Errors returned by Accept. The handler maps them to HTTP status codes.
var (
	ErrInvalid      = errors.New("invalid report")
	ErrConflict     = errors.New("instance name in use")
	ErrReplay       = errors.New("report is not newer than the last one")
	ErrTooManyPeers = errors.New("too many sidecars")
)

// Accept validates a report and stores it. ts is the signed timestamp.
func (s *Store) Accept(r Report, ts int64) (isNew bool, err error) {
	if !config.ValidInstanceName(r.Instance) {
		return false, fmt.Errorf("%w: bad instance name", ErrInvalid)
	}
	if r.Instance == s.local {
		return false, fmt.Errorf("%w: %q is the main container", ErrConflict, r.Instance)
	}
	if !versionRE.MatchString(r.Status.Version) {
		return false, fmt.Errorf("%w: bad version", ErrInvalid)
	}
	if len(r.Status.Records) > MaxRecords {
		return false, fmt.Errorf("%w: more than %d records", ErrInvalid, MaxRecords)
	}
	snap := r.Status
	snap.OK, snap.Errors, snap.Pending = 0, 0, 0
	for _, rec := range snap.Records {
		switch rec.State {
		case agent.StateOK:
			snap.OK++
		case agent.StateError:
			snap.Errors++
		case agent.StatePending:
			snap.Pending++
		default:
			return false, fmt.Errorf("%w: unknown record state", ErrInvalid)
		}
	}
	// Recomputed here instead of trusting the sidecar.
	snap.Healthy = !snap.RoundEnd.IsZero() && snap.Errors == 0 && snap.Pending == 0

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	e, ok := s.entries[r.Instance]
	if !ok {
		if len(s.entries) >= MaxInstances {
			return false, ErrTooManyPeers
		}
		e = &entry{}
		s.entries[r.Instance] = e
	} else if ts <= e.lastTS {
		return false, ErrReplay
	}
	e.lastTS = ts
	e.remote = Remote{Instance: r.Instance, Received: s.now(), Status: snap}
	return !ok, nil
}

// expire must be called with mu held.
func (s *Store) expire() {
	now := s.now()
	for k, e := range s.entries {
		if now.Sub(e.remote.Received) > ForgetAfter {
			delete(s.entries, k)
		}
	}
}

// Remotes returns the sidecars sorted by name.
func (s *Store) Remotes() []Remote {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	now := s.now()
	out := make([]Remote, 0, len(s.entries))
	for _, e := range s.entries {
		r := e.remote
		r.Status.Records = append([]agent.RecordStatus(nil), r.Status.Records...)
		r.Stale = now.Sub(r.Received) > StaleAfter
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Instance < out[j].Instance })
	return out
}

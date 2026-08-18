// Package flowstat maintains a cumulative record of which connectivity edges
// have actually been observed on the wire.
//
// This is deliberately separate from the Hubble ring buffer. The ring buffer
// evicts old records, so a low-frequency edge (a nightly batch job talking to a
// database) gets flushed out by high-frequency traffic and would then look like
// it never happened. Deriving "was this edge ever used?" from the ring buffer
// therefore produces false over-permission findings.
//
// Division of labour: the ring buffer holds flow detail for the recent past and
// is allowed to forget; this table holds one monotonic counter per edge for the
// whole observation window and never forgets.
//
// The package depends on nothing else inside the project so the dependency
// direction stays flowstat <- graph <- hubble, with no import cycle.
package flowstat

import (
	"sync"
	"time"
)

// EdgeKey identifies an observed connection. Src and Dst are static-graph node
// IDs (see graph.ResolveNodeID), not raw pod names, so observations line up
// with policy-derived edges.
//
// Port is part of the key on purpose. The most common form of over-permission
// is a policy opening a port range where only one port is ever used; keying on
// the node pair alone would classify every such edge as confirmed.
type EdgeKey struct {
	Src, Dst string
	Port     uint32
	Proto    string // "TCP" / "UDP"
}

// EdgeStat is the cumulative tally for one EdgeKey.
type EdgeStat struct {
	FirstSeen, LastSeen time.Time
	Forwarded, Dropped  int64
}

// Tracker is an append-only table of observed edges. Entries are never evicted.
type Tracker struct {
	mu      sync.RWMutex
	edges   map[EdgeKey]*EdgeStat
	started time.Time
}

func NewTracker() *Tracker {
	return &Tracker{
		edges:   make(map[EdgeKey]*EdgeStat),
		started: time.Now(),
	}
}

// Record tallies one observed flow against its edge.
func (t *Tracker) Record(k EdgeKey, dropped bool) {
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	stat, ok := t.edges[k]
	if !ok {
		stat = &EdgeStat{FirstSeen: now}
		t.edges[k] = stat
	}
	stat.LastSeen = now
	if dropped {
		stat.Dropped++
	} else {
		stat.Forwarded++
	}
}

// Snapshot returns a copy of the table plus the time observation started.
func (t *Tracker) Snapshot() (map[EdgeKey]EdgeStat, time.Time) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make(map[EdgeKey]EdgeStat, len(t.edges))
	for k, v := range t.edges {
		out[k] = *v
	}
	return out, t.started
}

// Started reports when this tracker began observing.
func (t *Tracker) Started() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.started
}

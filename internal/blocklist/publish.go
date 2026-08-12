package blocklist

import (
	"context"
	"log"
	"sync"
	"time"
)

// Source produces the current set of blocklist entries. Kept as a
// function type rather than an interface so internal/server can close
// over its gorm.DB/feed providers without this package depending on
// either — mirrors internal/firewall.Detect's dependency direction.
type Source func(ctx context.Context) ([]Entry, error)

// Publisher periodically regenerates and (re-)signs the blocklist on a
// ticker (PLAN.md M2: "ticker at --publish-interval (default 15m)").
// The most recently published SignedBlocklist is always available via
// Current, even if a later refresh fails — a Source error just skips
// that tick, it never clears what's already published.
type Publisher struct {
	Signer   Signer
	Source   Source
	Interval time.Duration
	TTL      time.Duration

	mu      sync.RWMutex
	current *SignedBlocklist
	version int
}

func NewPublisher(signer Signer, source Source, interval, ttl time.Duration) *Publisher {
	return &Publisher{Signer: signer, Source: source, Interval: interval, TTL: ttl}
}

// Current returns the most recently published blocklist, if any.
func (p *Publisher) Current() (*SignedBlocklist, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current, p.current != nil
}

// Refresh forces one publish cycle synchronously, outside of Run's
// ticker — used by tests, and available for a future `server run
// --publish-now`-style operator trigger.
func (p *Publisher) Refresh(ctx context.Context) {
	p.refresh(ctx)
}

// Run publishes once immediately (so GET /v1/blocklist has something
// to serve right after the server starts, not just after the first
// tick) and then on every Interval, until ctx is cancelled.
func (p *Publisher) Run(ctx context.Context) {
	p.refresh(ctx)
	interval := p.Interval
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.refresh(ctx)
		}
	}
}

func (p *Publisher) refresh(ctx context.Context) {
	entries, err := p.Source(ctx)
	if err != nil {
		log.Printf("blocklist publisher: source error, keeping last-published list: %v", err)
		return
	}

	p.mu.Lock()
	p.version++
	version := p.version
	p.mu.Unlock()

	bl := Blocklist{
		Version:     version,
		GeneratedAt: time.Now(),
		TTL:         p.TTL,
		Entries:     entries,
	}
	sig, err := p.Signer.Sign(bl)
	if err != nil {
		log.Printf("blocklist publisher: sign error, keeping last-published list: %v", err)
		return
	}

	p.mu.Lock()
	p.current = &SignedBlocklist{Blocklist: bl, Signature: sig, PublicKey: p.Signer.PublicKey()}
	p.mu.Unlock()
}

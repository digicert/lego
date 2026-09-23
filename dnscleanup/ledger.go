// Package dnscleanup implements a durable, cross-process ledger of DNS-01 TXT
// records that still need to be removed from a DNS provider.
package dnscleanup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

const DefaultTTL = 30 * time.Minute

const EnvTTL = "LEGO_DNS_CLEANUP_TTL"

const defaultLockTimeout = 30 * time.Second

const defaultCleanupTimeout = 30 * time.Second

const lockRetryDelay = 50 * time.Millisecond

type Cleaner interface {
	CleanUp(ctx context.Context, domain, token, keyAuth string) error
}

type Record struct {
	Domain        string     `json:"domain"`
	Value         string     `json:"value"`
	Scope         string     `json:"scope,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	Attempts      int        `json:"attempts,omitempty"`
	LastError     string     `json:"lastError,omitempty"`
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty"`
}

func (r Record) due(now time.Time, ttl time.Duration) bool {
	expiresAt := r.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = r.CreatedAt.Add(ttl)
	}

	return !now.Before(expiresAt)
}

func (r Record) cleanupScope() string {
	if r.Scope != "" {
		return r.Scope
	}

	return r.Domain
}

type ledgerFile struct {
	Provider string   `json:"provider"`
	Records  []Record `json:"records"`
}

type Ledger struct {
	path           string
	lockPath       string
	provider       string
	ttl            time.Duration
	maxAttempts    int
	lockTimeout    time.Duration
	cleanupTimeout time.Duration
}

type Option func(*Ledger)

func WithTTL(ttl time.Duration) Option {
	return func(l *Ledger) {
		if ttl > 0 {
			l.ttl = ttl
		}
	}
}

func WithMaxAttempts(n int) Option {
	return func(l *Ledger) {
		if n > 0 {
			l.maxAttempts = n
		}
	}
}

func WithCleanupTimeout(timeout time.Duration) Option {
	return func(l *Ledger) {
		if timeout > 0 {
			l.cleanupTimeout = timeout
		}
	}
}

func New(dir, provider string, opts ...Option) (*Ledger, error) { //nolint:wsl_v5,nolintlint
	name := sanitize(provider)
	if name == "" {
		return nil, errors.New("dnscleanup: provider name must not be empty")
	}

	if dir == "" {
		dir = "."
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("dnscleanup: create ledger directory %q: %w", dir, err)
	}

	path := filepath.Join(dir, "cleanup-"+name+".json")
	l := &Ledger{
		path:           path,
		lockPath:       path + ".lock",
		provider:       provider,
		ttl:            ttlFromEnv(),
		lockTimeout:    defaultLockTimeout,
		cleanupTimeout: defaultCleanupTimeout,
	}

	for _, opt := range opts {
		opt(l)
	}

	return l, nil
}

func (l *Ledger) Path() string { return l.path }

func (l *Ledger) TTL() time.Duration { return l.ttl }

func (l *Ledger) RefreshInterval() time.Duration {
	interval := l.ttl / 3
	if interval <= 0 {
		return time.Nanosecond
	}

	return interval
}

func (l *Ledger) Add(ctx context.Context, records ...Record) error { //nolint:wsl_v5,nolintlint
	if len(records) == 0 {
		return nil
	}

	unlock, err := l.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	f, err := l.load()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	existing := make(map[string]int, len(f.Records))
	for i, r := range f.Records {
		existing[key(r.Domain, r.Value)] = i
	}

	for _, r := range records {
		if r.Domain == "" || r.Value == "" {
			continue
		}

		if i, ok := existing[key(r.Domain, r.Value)]; ok {
			f.Records[i].CreatedAt = now
			f.Records[i].ExpiresAt = now.Add(l.ttl)
			if r.Scope != "" {
				f.Records[i].Scope = r.Scope
			}
			f.Records[i].Attempts = 0
			f.Records[i].LastError = ""
			f.Records[i].LastAttemptAt = nil

			continue
		}

		if r.CreatedAt.IsZero() {
			r.CreatedAt = now
		}
		if r.ExpiresAt.IsZero() {
			r.ExpiresAt = r.CreatedAt.Add(l.ttl)
		}

		f.Records = append(f.Records, r)
		existing[key(r.Domain, r.Value)] = len(f.Records) - 1
	}

	return l.save(f)
}

type SweepResult struct {
	Cleaned []Record
	Failed  []Record
	Dropped []Record
	Skipped int
}

// Sweep removes ledger records whose TTL has elapsed. A record is retained
// while another record sharing its cleanup scope is still fresh, since
// providers that delete a whole TXT rrset would destroy a challenge still
// being validated.
//
// supersededScopes lifts that protection for scopes about to be presented
// again, cleaning their records immediately rather than waiting out the TTL.
// These scopes MUST be passed before Present, while the rrset still holds only
// superseded values; passing them afterwards deletes the live challenge.
func (l *Ledger) Sweep(ctx context.Context, c Cleaner, supersededScopes ...string) (SweepResult, error) { //nolint:gocyclo,wsl_v5,nolintlint
	var res SweepResult

	if c == nil {
		return res, errors.New("dnscleanup: nil Cleaner")
	}

	unlock, err := l.lock(ctx)
	if err != nil {
		return res, err
	}
	defer unlock()

	f, err := l.load()
	if err != nil {
		return res, err
	}

	now := time.Now().UTC()
	kept := make([]Record, 0, len(f.Records))
	pending := append([]Record(nil), f.Records...)
	superseded := make(map[string]struct{}, len(supersededScopes))
	for _, scope := range supersededScopes {
		if scope = strings.TrimSpace(scope); scope != "" {
			superseded[scope] = struct{}{}
		}
	}

	protectedScopes := make(map[string]struct{})
	for _, r := range pending {
		scope := r.cleanupScope()
		if _, replaced := superseded[scope]; replaced {
			continue
		}
		if !r.due(now, l.ttl) {
			protectedScopes[scope] = struct{}{}
		}
	}

	for i, r := range pending {
		scope := r.cleanupScope()
		_, replaced := superseded[scope]
		_, protected := protectedScopes[scope]
		if !replaced && (!r.due(now, l.ttl) || protected) {
			res.Skipped++
			kept = append(kept, r)

			continue
		}

		cleanupCtx, cancel := context.WithTimeout(ctx, l.cleanupTimeout)
		cleanErr := c.CleanUp(cleanupCtx, r.Domain, "", r.Value)
		cancel()
		if cleanErr == nil {
			res.Cleaned = append(res.Cleaned, r)
			f.Records = append(append([]Record(nil), kept...), pending[i+1:]...)
			if err := l.save(f); err != nil {
				return res, err
			}

			continue
		}

		attempt := now
		r.Attempts++
		r.LastError = cleanErr.Error()
		r.LastAttemptAt = &attempt

		if l.maxAttempts > 0 && r.Attempts >= l.maxAttempts {
			res.Dropped = append(res.Dropped, r)

			continue
		}

		res.Failed = append(res.Failed, r)
		kept = append(kept, r)
	}

	f.Records = kept

	return res, l.save(f)
}

func (l *Ledger) lock(ctx context.Context) (func(), error) { //nolint:wsl_v5,nolintlint
	if ctx == nil {
		ctx = context.Background()
	}

	lockCtx, cancel := context.WithTimeout(ctx, l.lockTimeout)
	defer cancel()

	fl := flock.New(l.lockPath)
	ok, err := fl.TryLockContext(lockCtx, lockRetryDelay)
	if err != nil {
		return nil, fmt.Errorf("dnscleanup: lock %q: %w", l.lockPath, err)
	}
	if !ok {
		return nil, fmt.Errorf("dnscleanup: timed out after %s waiting for lock %q", l.lockTimeout, l.lockPath)
	}

	return func() { _ = fl.Unlock() }, nil
}

func (l *Ledger) load() (*ledgerFile, error) { //nolint:wsl_v5,nolintlint
	data, err := os.ReadFile(l.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &ledgerFile{Provider: l.provider}, nil
		}

		return nil, fmt.Errorf("dnscleanup: read %q: %w", l.path, err)
	}

	if strings.TrimSpace(string(data)) == "" {
		return &ledgerFile{Provider: l.provider}, nil
	}

	var f ledgerFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("dnscleanup: parse %q (left intact for inspection): %w", l.path, err)
	}
	if f.Provider == "" {
		f.Provider = l.provider
	}

	return &f, nil
}

func (l *Ledger) save(f *ledgerFile) error { //nolint:wsl_v5,nolintlint
	if f.Records == nil {
		f.Records = []Record{}
	}

	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("dnscleanup: encode ledger: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(l.path), filepath.Base(l.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("dnscleanup: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("dnscleanup: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("dnscleanup: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, l.path); err != nil {
		return fmt.Errorf("dnscleanup: replace %q: %w", l.path, err)
	}

	return nil
}

func ttlFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv(EnvTTL))
	if raw == "" {
		return DefaultTTL
	}

	ttl, err := time.ParseDuration(raw)
	if err != nil || ttl <= 0 {
		return DefaultTTL
	}

	return ttl
}

func key(domain, value string) string {
	return domain + "\x00" + value
}

func sanitize(provider string) string { //nolint:wsl_v5,nolintlint
	provider = strings.TrimSpace(provider)
	var b strings.Builder
	for _, r := range provider {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}

	return strings.Trim(b.String(), "_")
}

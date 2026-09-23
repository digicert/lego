package dnscleanup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeCleaner struct {
	mu    sync.Mutex
	calls []cleanCall
	fail  func(domain, value string) error
}

type cleanCall struct {
	domain string
	token  string
	value  string
}

func (f *fakeCleaner) CleanUp(_ context.Context, domain, token, keyAuth string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, cleanCall{domain: domain, token: token, value: keyAuth})

	if f.fail != nil {
		return f.fail(domain, keyAuth)
	}

	return nil
}

type blockingCleaner struct{}

func (blockingCleaner) CleanUp(ctx context.Context, _, _, _ string) error {
	<-ctx.Done()

	return ctx.Err()
}

func newLedger(t *testing.T, opts ...Option) *Ledger {
	t.Helper()

	l, err := New(t.TempDir(), "ultradns", opts...)
	require.NoError(t, err)

	return l
}

func readFile(t *testing.T, l *Ledger) ledgerFile {
	t.Helper()

	data, err := os.ReadFile(l.Path())
	require.NoError(t, err)

	var f ledgerFile

	require.NoError(t, json.Unmarshal(data, &f))

	return f
}

func TestSweepPassesStoredValue(t *testing.T) {
	l := newLedger(t, WithTTL(time.Nanosecond))
	require.NoError(t, l.Add(context.Background(), Record{Domain: "example.com", Value: "exact-value"}))

	fake := &fakeCleaner{}

	res, err := l.Sweep(context.Background(), fake)
	require.NoError(t, err)
	require.Len(t, fake.calls, 1)

	assert.Equal(t, "exact-value", fake.calls[0].value)
	assert.Len(t, res.Cleaned, 1)
	assert.Empty(t, readFile(t, l).Records)
}

func TestSweepProtectsFreshCleanupScope(t *testing.T) {
	l := newLedger(t, WithTTL(30*time.Minute))
	now := time.Now().UTC()

	require.NoError(t, l.Add(context.Background(),
		Record{Domain: "example.com", Value: "old", Scope: "_acme-challenge.example.com.", CreatedAt: now.Add(-time.Hour)},
		Record{Domain: "*.example.com", Value: "fresh", Scope: "_acme-challenge.example.com.", CreatedAt: now},
	))

	fake := &fakeCleaner{}

	res, err := l.Sweep(context.Background(), fake)
	require.NoError(t, err)

	assert.Empty(t, fake.calls)
	assert.Equal(t, 2, res.Skipped)
}

func TestSweepCleansSupersededScopeImmediately(t *testing.T) {
	l := newLedger(t, WithTTL(30*time.Minute))
	scope := "_acme-challenge.finaldnsmadeeasy.example.us."

	require.NoError(t, l.Add(context.Background(),
		Record{Domain: "finaldnsmadeeasy.example.us", Value: "first", Scope: scope},
		Record{Domain: "finaldnsmadeeasy.example.us", Value: "second", Scope: scope},
	))

	fake := &fakeCleaner{}

	res, err := l.Sweep(context.Background(), fake, Intent{Scope: scope, Value: "third"})
	require.NoError(t, err)
	require.Len(t, fake.calls, 2)

	assert.Equal(t, []string{"first", "second"}, []string{fake.calls[0].value, fake.calls[1].value})
	assert.Len(t, res.Cleaned, 2)
	assert.Zero(t, res.Skipped)
	assert.Empty(t, readFile(t, l).Records)
}

func TestSweepPreservesValueBeingRepresented(t *testing.T) {
	l := newLedger(t, WithTTL(30*time.Minute))
	scope := "_acme-challenge.retry.example.com."

	require.NoError(t, l.Add(context.Background(),
		Record{Domain: "retry.example.com", Value: "stale", Scope: scope},
		Record{Domain: "retry.example.com", Value: "current", Scope: scope},
	))

	fake := &fakeCleaner{}

	res, err := l.Sweep(context.Background(), fake, Intent{Scope: scope, Value: "current"})
	require.NoError(t, err)
	require.Len(t, fake.calls, 1)

	assert.Equal(t, "stale", fake.calls[0].value)
	assert.Equal(t, 1, res.Skipped)

	records := readFile(t, l).Records
	require.Len(t, records, 1)

	assert.Equal(t, "current", records[0].Value)
}

func TestSweepKeepsUnrelatedScopeProtectedWhileSuperseding(t *testing.T) {
	l := newLedger(t, WithTTL(30*time.Minute))
	superseded := "_acme-challenge.retry.example.com."

	require.NoError(t, l.Add(context.Background(),
		Record{Domain: "retry.example.com", Value: "stale", Scope: superseded},
		Record{Domain: "other.example.com", Value: "live", Scope: "_acme-challenge.other.example.com."},
	))

	fake := &fakeCleaner{}

	res, err := l.Sweep(context.Background(), fake, Intent{Scope: superseded, Value: "replacement"})
	require.NoError(t, err)
	require.Len(t, fake.calls, 1)

	assert.Equal(t, "stale", fake.calls[0].value)
	assert.Equal(t, 1, res.Skipped)

	records := readFile(t, l).Records
	require.Len(t, records, 1)

	assert.Equal(t, "live", records[0].Value)
}

func TestSweepBoundsProviderCall(t *testing.T) {
	l, err := New(t.TempDir(), "slow", WithTTL(time.Nanosecond), WithCleanupTimeout(20*time.Millisecond))
	require.NoError(t, err)
	require.NoError(t, l.Add(context.Background(), Record{
		Domain:    "slow.example.com",
		Value:     "slow",
		CreatedAt: time.Now().UTC().Add(-time.Second),
	}))

	res, err := l.Sweep(context.Background(), blockingCleaner{})
	require.NoError(t, err)
	require.Len(t, res.Failed, 1)

	assert.Contains(t, res.Failed[0].LastError, context.DeadlineExceeded.Error())
}

func TestSweepRetainsFailure(t *testing.T) {
	l := newLedger(t, WithTTL(time.Nanosecond))
	require.NoError(t, l.Add(context.Background(), Record{Domain: "bad.example.com", Value: "bad"}))

	fake := &fakeCleaner{fail: func(string, string) error { return errors.New("failed") }}

	res, err := l.Sweep(context.Background(), fake)
	require.NoError(t, err)
	require.Len(t, res.Failed, 1)

	records := readFile(t, l).Records
	require.Len(t, records, 1)

	assert.Equal(t, 1, records[0].Attempts)
	assert.Equal(t, "failed", records[0].LastError)
}

func TestAddRefreshesDuplicateReservation(t *testing.T) {
	l := newLedger(t, WithTTL(30*time.Minute))
	old := time.Now().UTC().Add(-time.Hour)

	require.NoError(t, l.Add(context.Background(), Record{Domain: "retry.example.com", Value: "retry", CreatedAt: old, Attempts: 2}))
	require.NoError(t, l.Add(context.Background(), Record{Domain: "retry.example.com", Value: "retry"}))

	records := readFile(t, l).Records
	require.Len(t, records, 1)

	assert.True(t, records[0].CreatedAt.After(old))
	assert.Zero(t, records[0].Attempts)
}

func TestConcurrentAddsDoNotLoseRecords(t *testing.T) {
	dir := t.TempDir()

	var wg sync.WaitGroup

	errCh := make(chan error, 8)

	for i := range 8 {
		wg.Go(func() {
			l, err := New(dir, "ultradns")
			if err != nil {
				errCh <- err

				return
			}

			errCh <- l.Add(context.Background(), Record{Domain: fmt.Sprintf("host%d.example.com", i), Value: fmt.Sprintf("value-%d", i)})
		})
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}

	l, err := New(dir, "ultradns")
	require.NoError(t, err)

	assert.Len(t, readFile(t, l).Records, 8)
}

func TestProviderNameCannotEscapeDirectory(t *testing.T) {
	dir := t.TempDir()

	l, err := New(dir, "../../etc/passwd")
	require.NoError(t, err)

	assert.Equal(t, dir, filepath.Dir(l.Path()))
}

func TestTTLResolution(t *testing.T) {
	l := newLedger(t)
	assert.Equal(t, 30*time.Minute, l.TTL())

	t.Setenv(EnvTTL, "6h")

	l = newLedger(t)
	assert.Equal(t, 6*time.Hour, l.TTL())
}

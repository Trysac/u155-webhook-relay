package webhookrelay

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// ErrInvalidConfig is returned by New when configuration validation fails.
var ErrInvalidConfig = errors.New("webhookrelay: invalid config")

const (
	defaultSignatureHeader = "X-Hub-Signature-256"
	defaultMaxBodyBytes    = int64(1 << 20) // 1 MiB
	defaultMaxAttempts     = 5
	defaultBaseBackoff     = 1 * time.Second
	defaultMaxBackoff      = 60 * time.Second
	defaultAttemptTimeout  = 10 * time.Second
	maxDeadLetters         = 100
	maxResponseReadBytes   = 64 * 1024 // 64 KiB
	maxErrorRuneBytes      = 200
)

// Doer abstracts the HTTP client Do method for testability.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config holds configuration parameters for Relay.
type Config struct {
	InboundSecret   []byte
	SignatureHeader string
	TargetURL       string
	OutboundSecret  []byte
	MaxBodyBytes    int64
	QueueSize       int
	MaxAttempts     int
	BaseBackoff     time.Duration
	MaxBackoff      time.Duration
	AttemptTimeout  time.Duration
	Client          Doer
	Sleep           func(ctx context.Context, d time.Duration) error
	OnEvent         func(Event)
}

// Event describes a lifecycle transition of an inbound webhook item.
type Event struct {
	Kind    string
	ID      string
	Attempt int
	Status  int
	Reason  string
}

// Stats summarizes relay queue and delivery counters.
type Stats struct {
	Queued       int
	Delivered    int
	DeadLettered int
}

// DeadLetter represents a failed webhook delivery that exceeded retries or unretryable error.
type DeadLetter struct {
	ID         string
	Attempts   int
	LastStatus int
	LastError  string
}

type queueItem struct {
	id          string
	body        []byte
	contentType string
}

// Relay is an HTTP handler and delivery worker for store-and-forward webhooks.
type Relay struct {
	cfg Config

	mu          sync.Mutex
	queue       []*queueItem
	wakeCh      chan struct{}
	delivered   int
	deadLetters []DeadLetter
	idCounter   uint64
}

// New creates a new validated Relay instance.
func New(cfg Config) (*Relay, error) {
	if len(cfg.InboundSecret) == 0 {
		return nil, fmt.Errorf("%w: InboundSecret is required", ErrInvalidConfig)
	}
	if cfg.QueueSize < 1 || cfg.QueueSize > 100000 {
		return nil, fmt.Errorf("%w: QueueSize must be between 1 and 100000", ErrInvalidConfig)
	}
	if cfg.TargetURL == "" {
		return nil, fmt.Errorf("%w: TargetURL is required", ErrInvalidConfig)
	}
	parsedURL, err := url.Parse(cfg.TargetURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		return nil, fmt.Errorf("%w: TargetURL must have http or https scheme", ErrInvalidConfig)
	}

	if cfg.SignatureHeader == "" {
		cfg.SignatureHeader = defaultSignatureHeader
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = defaultBaseBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = defaultMaxBackoff
	}
	if cfg.AttemptTimeout <= 0 {
		cfg.AttemptTimeout = defaultAttemptTimeout
	}
	if cfg.Client == nil {
		cfg.Client = http.DefaultClient
	}
	if cfg.Sleep == nil {
		cfg.Sleep = defaultSleep
	}

	return &Relay{
		cfg:         cfg,
		queue:       make([]*queueItem, 0, cfg.QueueSize),
		wakeCh:      make(chan struct{}, 1),
		deadLetters: make([]DeadLetter, 0, maxDeadLetters),
	}, nil
}

func defaultSleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (r *Relay) emit(ev Event) {
	if r.cfg.OnEvent != nil {
		r.cfg.OnEvent(ev)
	}
}

// ServeHTTP handles inbound webhook POST requests.
func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		r.emit(Event{Kind: "rejected", Reason: "method not allowed", Status: http.StatusMethodNotAllowed})
		return
	}

	if req.ContentLength > r.cfg.MaxBodyBytes {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		r.emit(Event{Kind: "rejected", Reason: "request entity too large", Status: http.StatusRequestEntityTooLarge})
		return
	}

	maxReader := io.LimitReader(req.Body, r.cfg.MaxBodyBytes+1)
	body, err := io.ReadAll(maxReader)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		r.emit(Event{Kind: "rejected", Reason: "failed to read body", Status: http.StatusBadRequest})
		return
	}
	if int64(len(body)) > r.cfg.MaxBodyBytes {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		r.emit(Event{Kind: "rejected", Reason: "request entity too large", Status: http.StatusRequestEntityTooLarge})
		return
	}

	sigHeader := req.Header.Get(r.cfg.SignatureHeader)
	if !r.verifyInboundSignature(sigHeader, body) {
		w.WriteHeader(http.StatusUnauthorized)
		r.emit(Event{Kind: "rejected", Reason: "unauthorized", Status: http.StatusUnauthorized})
		return
	}

	idNum := atomic.AddUint64(&r.idCounter, 1)
	deliveryID := fmt.Sprintf("d-%d", idNum)

	contentType := req.Header.Get("Content-Type")
	item := &queueItem{
		id:          deliveryID,
		body:        body,
		contentType: contentType,
	}

	r.mu.Lock()
	if len(r.queue) >= r.cfg.QueueSize {
		r.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		r.emit(Event{Kind: "rejected", ID: deliveryID, Reason: "queue full", Status: http.StatusServiceUnavailable})
		return
	}
	r.queue = append(r.queue, item)
	select {
	case r.wakeCh <- struct{}{}:
	default:
	}
	r.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	rb, _ := json.Marshal(map[string]string{"id": deliveryID})
	w.Write(append(rb, '\n'))

	r.emit(Event{Kind: "accepted", ID: deliveryID, Status: http.StatusAccepted})
}

func (r *Relay) verifyInboundSignature(headerVal string, body []byte) bool {
	if headerVal == "" {
		return false
	}
	const prefix = "sha256="
	if !strings.HasPrefix(headerVal, prefix) {
		return false
	}
	hexSig := strings.TrimPrefix(headerVal, prefix)
	if len(hexSig) != 64 {
		return false
	}
	for i := 0; i < len(hexSig); i++ {
		c := hexSig[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	sigBytes, err := hex.DecodeString(hexSig)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, r.cfg.InboundSecret)
	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(sigBytes, expectedMAC)
}

// Run delivers queued items sequentially until ctx is canceled.
func (r *Relay) Run(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		item := r.peekQueue()
		if item == nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-r.wakeCh:
				continue
			}
		}

		err := r.deliverItem(ctx, item)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
		}
	}
}

func (r *Relay) peekQueue() *queueItem {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.queue) == 0 {
		return nil
	}
	return r.queue[0]
}

func (r *Relay) popQueue() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.queue) > 0 {
		r.queue = r.queue[1:]
	}
}

func (r *Relay) deliverItem(ctx context.Context, item *queueItem) error {
	attempt := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		attempt++

		status, retryAfterSec, err := r.executeAttempt(ctx, item, attempt)

		if status >= 200 && status <= 299 {
			r.mu.Lock()
			r.delivered++
			r.mu.Unlock()
			r.popQueue()
			r.emit(Event{Kind: "delivered", ID: item.id, Attempt: attempt, Status: status})
			return nil
		}

		isRetryable := (err != nil) || (status == 408) || (status == 429) || (status >= 500 && status <= 599)
		if !isRetryable {
			errStr := fmt.Sprintf("delivery failed with status %d", status)
			r.recordDeadLetter(item.id, attempt, status, errStr)
			r.popQueue()
			r.emit(Event{Kind: "dead_letter", ID: item.id, Attempt: attempt, Status: status, Reason: errStr})
			return nil
		}

		if attempt >= r.cfg.MaxAttempts {
			errStr := ""
			if err != nil {
				errStr = err.Error()
			} else {
				errStr = fmt.Sprintf("delivery failed with status %d", status)
			}
			r.recordDeadLetter(item.id, attempt, status, errStr)
			r.popQueue()
			r.emit(Event{Kind: "dead_letter", ID: item.id, Attempt: attempt, Status: status, Reason: errStr})
			return nil
		}

		backoff := r.computeBackoff(attempt, retryAfterSec)
		reasonStr := ""
		if err != nil {
			reasonStr = err.Error()
		} else {
			reasonStr = fmt.Sprintf("status %d", status)
		}
		r.emit(Event{Kind: "retry", ID: item.id, Attempt: attempt, Status: status, Reason: reasonStr})

		sleepErr := r.cfg.Sleep(ctx, backoff)
		if sleepErr != nil {
			return sleepErr
		}
	}
}

func (r *Relay) computeBackoff(attempt int, retryAfterSec int) time.Duration {
	if retryAfterSec > 0 {
		d := time.Duration(retryAfterSec) * time.Second
		if d > r.cfg.MaxBackoff {
			return r.cfg.MaxBackoff
		}
		return d
	}

	shift := attempt - 1
	if shift < 0 {
		shift = 0
	}
	if shift > 30 {
		return r.cfg.MaxBackoff
	}
	multiplier := time.Duration(1) << shift
	backoff := r.cfg.BaseBackoff * multiplier
	if backoff > r.cfg.MaxBackoff || backoff < 0 {
		return r.cfg.MaxBackoff
	}
	return backoff
}

func (r *Relay) executeAttempt(ctx context.Context, item *queueItem, attempt int) (int, int, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, r.cfg.AttemptTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, r.cfg.TargetURL, bytes.NewReader(item.body))
	if err != nil {
		return 0, 0, err
	}

	if item.contentType != "" {
		req.Header.Set("Content-Type", item.contentType)
	}
	req.Header.Set("X-Relay-Delivery", item.id)
	req.Header.Set("X-Relay-Attempt", strconv.Itoa(attempt))

	if len(r.cfg.OutboundSecret) > 0 {
		mac := hmac.New(sha256.New, r.cfg.OutboundSecret)
		mac.Write(item.body)
		sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Relay-Signature", sig)
	}

	resp, err := r.cfg.Client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseReadBytes))

	retryAfterSec := 0
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		ra := strings.TrimSpace(resp.Header.Get("Retry-After"))
		if len(ra) >= 1 && len(ra) <= 6 {
			if val, parseErr := strconv.Atoi(ra); parseErr == nil && val > 0 {
				retryAfterSec = val
			}
		}
	}

	return resp.StatusCode, retryAfterSec, nil
}

func (r *Relay) recordDeadLetter(id string, attempts int, lastStatus int, lastError string) {
	cleanError := sanitizeError(lastError, maxErrorRuneBytes)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.deadLetters) >= maxDeadLetters {
		r.deadLetters = r.deadLetters[1:]
	}
	r.deadLetters = append(r.deadLetters, DeadLetter{
		ID:         id,
		Attempts:   attempts,
		LastStatus: lastStatus,
		LastError:  cleanError,
	})
}

func sanitizeError(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if b.Len()+utf8.RuneLen(r) > maxBytes {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Stats returns a snapshot of current queued, delivered, and dead-lettered counts.
func (r *Relay) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Stats{
		Queued:       len(r.queue),
		Delivered:    r.delivered,
		DeadLettered: len(r.deadLetters),
	}
}

// DeadLetters returns a copy of stored dead letter entries.
func (r *Relay) DeadLetters() []DeadLetter {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]DeadLetter, len(r.deadLetters))
	copy(out, r.deadLetters)
	return out
}

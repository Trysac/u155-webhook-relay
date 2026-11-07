package webhookrelay_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	webhookrelay "github.com/Trysac/u155-webhook-relay"
)

type fakeDoer struct {
	mu       sync.Mutex
	handlers []func(req *http.Request) (*http.Response, error)
	calls    []*http.Request
	bodies   [][]byte
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	idx := len(f.calls)
	f.calls = append(f.calls, req)
	bodyBytes, _ := io.ReadAll(req.Body)
	f.bodies = append(f.bodies, bodyBytes)
	var handler func(req *http.Request) (*http.Response, error)
	if idx < len(f.handlers) {
		handler = f.handlers[idx]
	}
	f.mu.Unlock()

	if handler != nil {
		return handler(req)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(nil)),
		Header:     make(http.Header),
	}, nil
}

func calcHMAC(secret []byte, data []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write(data)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

// Acceptance 1: With InboundSecret "It's a Secret to Everybody", a POST with body "Hello, World!"
// and X-Hub-Signature-256 "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
// (GitHub docs example) gets 202 with body `{"id":"d-1"}` + "\n";
// a wrong or missing signature gets 401; GET gets 405 with Allow "POST"
func TestAcceptance1_InboundSignatureAndMethods(t *testing.T) {
	inboundSecret := []byte("It's a Secret to Everybody")
	body := []byte("Hello, World!")
	validSig := "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"

	relay, err := webhookrelay.New(webhookrelay.Config{
		InboundSecret: inboundSecret,
		TargetURL:     "https://example.com/webhook",
		QueueSize:     10,
	})
	if err != nil {
		t.Fatalf("unexpected error from New: %v", err)
	}

	// Valid POST
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", validSig)
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
	wantBody := "{\"id\":\"d-1\"}\n"
	if rec.Body.String() != wantBody {
		t.Fatalf("expected body %q, got %q", wantBody, rec.Body.String())
	}

	// Wrong signature
	reqWrong := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	reqWrong.Header.Set("X-Hub-Signature-256", "sha256=0000000000000000000000000000000000000000000000000000000000000000")
	recWrong := httptest.NewRecorder()
	relay.ServeHTTP(recWrong, reqWrong)
	if recWrong.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong signature, got %d", recWrong.Code)
	}
	if recWrong.Body.Len() != 0 {
		t.Fatalf("expected empty body for 401, got %q", recWrong.Body.String())
	}

	// Missing signature
	reqMissing := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	recMissing := httptest.NewRecorder()
	relay.ServeHTTP(recMissing, reqMissing)
	if recMissing.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing signature, got %d", recMissing.Code)
	}

	// Invalid format signature
	reqBadFormat := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	reqBadFormat.Header.Set("X-Hub-Signature-256", "invalid_signature")
	recBadFormat := httptest.NewRecorder()
	relay.ServeHTTP(recBadFormat, reqBadFormat)
	if recBadFormat.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid formatted signature, got %d", recBadFormat.Code)
	}

	// GET method
	reqGet := httptest.NewRequest(http.MethodGet, "/", nil)
	recGet := httptest.NewRecorder()
	relay.ServeHTTP(recGet, reqGet)
	if recGet.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET, got %d", recGet.Code)
	}
	if allow := recGet.Header().Get("Allow"); allow != "POST" {
		t.Fatalf("expected Allow: POST, got %q", allow)
	}
}

// Acceptance 2: A body of MaxBodyBytes + 1 bytes gets 413 and nothing is queued;
// with QueueSize 2 and two queued items a third valid request gets 503 and Stats().Queued == 2
func TestAcceptance2_MaxBodyAndQueueLimit(t *testing.T) {
	inboundSecret := []byte("secret")
	maxBody := int64(10)
	relay, err := webhookrelay.New(webhookrelay.Config{
		InboundSecret: inboundSecret,
		TargetURL:     "https://example.com/webhook",
		MaxBodyBytes:  maxBody,
		QueueSize:     2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Body of MaxBodyBytes + 1 bytes
	overflowBody := bytes.Repeat([]byte("a"), int(maxBody+1))
	sig := calcHMAC(inboundSecret, overflowBody)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(overflowBody))
	req.Header.Set("X-Hub-Signature-256", sig)
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rec.Code)
	}
	if relay.Stats().Queued != 0 {
		t.Fatalf("expected queued 0, got %d", relay.Stats().Queued)
	}

	// Enqueue item 1
	body1 := []byte("item1")
	req1 := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body1))
	req1.Header.Set("X-Hub-Signature-256", calcHMAC(inboundSecret, body1))
	rec1 := httptest.NewRecorder()
	relay.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for item 1, got %d", rec1.Code)
	}

	// Enqueue item 2
	body2 := []byte("item2")
	req2 := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body2))
	req2.Header.Set("X-Hub-Signature-256", calcHMAC(inboundSecret, body2))
	rec2 := httptest.NewRecorder()
	relay.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for item 2, got %d", rec2.Code)
	}

	// Third item with QueueSize 2 gets 503
	body3 := []byte("item3")
	req3 := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body3))
	req3.Header.Set("X-Hub-Signature-256", calcHMAC(inboundSecret, body3))
	rec3 := httptest.NewRecorder()
	relay.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for item 3, got %d", rec3.Code)
	}
	if relay.Stats().Queued != 2 {
		t.Fatalf("expected Stats().Queued == 2, got %d", relay.Stats().Queued)
	}
}

// Acceptance 3: Run sends to the fake Doer a POST to TargetURL with body exactly "Hello, World!",
// X-Relay-Signature "sha256=9520ebf945b6b993b4e3f600ec89887ec2cb768bea64e041212acc403a685acf"
// for OutboundSecret "out", X-Relay-Delivery "d-1" and X-Relay-Attempt "1"
func TestAcceptance3_RunDeliveryAndHeaders(t *testing.T) {
	inboundSecret := []byte("in")
	outboundSecret := []byte("out")
	body := []byte("Hello, World!")
	targetURL := "https://example.com/target"

	fake := &fakeDoer{
		handlers: []func(req *http.Request) (*http.Response, error){
			func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("ok")),
				}, nil
			},
		},
	}

	relay, err := webhookrelay.New(webhookrelay.Config{
		InboundSecret:  inboundSecret,
		OutboundSecret: outboundSecret,
		TargetURL:      targetURL,
		QueueSize:      10,
		Client:         fake,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Hub-Signature-256", calcHMAC(inboundSecret, body))
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			if relay.Stats().Delivered == 1 {
				cancel()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	_ = relay.Run(ctx)

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(fake.calls))
	}
	httpReq := fake.calls[0]
	if httpReq.Method != http.MethodPost {
		t.Errorf("expected POST, got %s", httpReq.Method)
	}
	if httpReq.URL.String() != targetURL {
		t.Errorf("expected URL %s, got %s", targetURL, httpReq.URL.String())
	}
	if string(fake.bodies[0]) != "Hello, World!" {
		t.Errorf("expected body 'Hello, World!', got %q", string(fake.bodies[0]))
	}
	wantSig := "sha256=9520ebf945b6b993b4e3f600ec89887ec2cb768bea64e041212acc403a685acf"
	if sig := httpReq.Header.Get("X-Relay-Signature"); sig != wantSig {
		t.Errorf("expected X-Relay-Signature %s, got %s", wantSig, sig)
	}
	if del := httpReq.Header.Get("X-Relay-Delivery"); del != "d-1" {
		t.Errorf("expected X-Relay-Delivery d-1, got %s", del)
	}
	if att := httpReq.Header.Get("X-Relay-Attempt"); att != "1" {
		t.Errorf("expected X-Relay-Attempt 1, got %s", att)
	}
	if ct := httpReq.Header.Get("Content-Type"); ct != "text/plain" {
		t.Errorf("expected Content-Type text/plain, got %s", ct)
	}
}

// Acceptance 4: Responses 500, 503 then 200 make Sleep receive [1s, 2s] with BaseBackoff 1*time.Second,
// attempt headers "1", "2", "3" and Stats().Delivered == 1
func TestAcceptance4_ExponentialBackoff(t *testing.T) {
	inboundSecret := []byte("in")
	body := []byte("msg")

	fake := &fakeDoer{
		handlers: []func(req *http.Request) (*http.Response, error){
			func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 500, Body: io.NopCloser(bytes.NewReader(nil))}, nil
			},
			func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 503, Body: io.NopCloser(bytes.NewReader(nil))}, nil
			},
			func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(nil))}, nil
			},
		},
	}

	var sleepMu sync.Mutex
	var sleepDurations []time.Duration
	fakeSleep := func(ctx context.Context, d time.Duration) error {
		sleepMu.Lock()
		sleepDurations = append(sleepDurations, d)
		sleepMu.Unlock()
		return nil
	}

	relay, err := webhookrelay.New(webhookrelay.Config{
		InboundSecret: inboundSecret,
		TargetURL:     "https://example.com/target",
		QueueSize:     10,
		BaseBackoff:   1 * time.Second,
		Client:        fake,
		Sleep:         fakeSleep,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", calcHMAC(inboundSecret, body))
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			if relay.Stats().Delivered == 1 {
				cancel()
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	_ = relay.Run(ctx)

	sleepMu.Lock()
	wantSleeps := []time.Duration{1 * time.Second, 2 * time.Second}
	if len(sleepDurations) != len(wantSleeps) {
		t.Fatalf("expected sleeps %v, got %v", wantSleeps, sleepDurations)
	}
	for i := range wantSleeps {
		if sleepDurations[i] != wantSleeps[i] {
			t.Errorf("sleep[%d]: expected %v, got %v", i, wantSleeps[i], sleepDurations[i])
		}
	}
	sleepMu.Unlock()

	fake.mu.Lock()
	if len(fake.calls) != 3 {
		t.Fatalf("expected 3 calls, got %d", len(fake.calls))
	}
	wantAttempts := []string{"1", "2", "3"}
	for i, c := range fake.calls {
		if got := c.Header.Get("X-Relay-Attempt"); got != wantAttempts[i] {
			t.Errorf("call %d: expected attempt header %s, got %s", i, wantAttempts[i], got)
		}
	}
	fake.mu.Unlock()

	if relay.Stats().Delivered != 1 {
		t.Errorf("expected Stats().Delivered == 1, got %d", relay.Stats().Delivered)
	}
}

// Acceptance 5: A 429 with Retry-After "7" makes the next Sleep 7*time.Second,
// and Retry-After "120" with MaxBackoff 60*time.Second makes it 60*time.Second
func TestAcceptance5_RetryAfterHeader(t *testing.T) {
	inboundSecret := []byte("in")
	body := []byte("retry_after_test")

	fake := &fakeDoer{
		handlers: []func(req *http.Request) (*http.Response, error){
			func(req *http.Request) (*http.Response, error) {
				h := make(http.Header)
				h.Set("Retry-After", "7")
				return &http.Response{StatusCode: 429, Header: h, Body: io.NopCloser(bytes.NewReader(nil))}, nil
			},
			func(req *http.Request) (*http.Response, error) {
				h := make(http.Header)
				h.Set("Retry-After", "120")
				return &http.Response{StatusCode: 429, Header: h, Body: io.NopCloser(bytes.NewReader(nil))}, nil
			},
			func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(nil))}, nil
			},
		},
	}

	var sleepMu sync.Mutex
	var sleepDurations []time.Duration
	fakeSleep := func(ctx context.Context, d time.Duration) error {
		sleepMu.Lock()
		sleepDurations = append(sleepDurations, d)
		sleepMu.Unlock()
		return nil
	}

	relay, err := webhookrelay.New(webhookrelay.Config{
		InboundSecret: inboundSecret,
		TargetURL:     "https://example.com/target",
		QueueSize:     10,
		MaxBackoff:    60 * time.Second,
		Client:        fake,
		Sleep:         fakeSleep,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", calcHMAC(inboundSecret, body))
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			if relay.Stats().Delivered == 1 {
				cancel()
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	_ = relay.Run(ctx)

	sleepMu.Lock()
	defer sleepMu.Unlock()
	if len(sleepDurations) != 2 {
		t.Fatalf("expected 2 sleeps, got %d: %v", len(sleepDurations), sleepDurations)
	}
	if sleepDurations[0] != 7*time.Second {
		t.Errorf("expected sleep 7s, got %v", sleepDurations[0])
	}
	if sleepDurations[1] != 60*time.Second {
		t.Errorf("expected sleep 60s (capped), got %v", sleepDurations[1])
	}
}

// Acceptance 6: A 400 response is not retried and yields one DeadLetter with Attempts 1 and LastStatus 400;
// five 500 responses with MaxAttempts 5 yield Sleep [1s, 2s, 4s, 8s] and a DeadLetter with Attempts 5;
// the 101st dead letter evicts the oldest so len(DeadLetters()) == 100
func TestAcceptance6_DeadLettersAndEviction(t *testing.T) {
	inboundSecret := []byte("in")

	t.Run("400 is not retried", func(t *testing.T) {
		body := []byte("bad-req")
		fake := &fakeDoer{
			handlers: []func(req *http.Request) (*http.Response, error){
				func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 400, Body: io.NopCloser(bytes.NewReader(nil))}, nil
				},
			},
		}
		sleepCalled := false
		fakeSleep := func(ctx context.Context, d time.Duration) error {
			sleepCalled = true
			return nil
		}

		relay, err := webhookrelay.New(webhookrelay.Config{
			InboundSecret: inboundSecret,
			TargetURL:     "https://example.com/target",
			QueueSize:     10,
			Client:        fake,
			Sleep:         fakeSleep,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set("X-Hub-Signature-256", calcHMAC(inboundSecret, body))
		rec := httptest.NewRecorder()
		relay.ServeHTTP(rec, req)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			for {
				if len(relay.DeadLetters()) == 1 {
					cancel()
					return
				}
				time.Sleep(2 * time.Millisecond)
			}
		}()
		_ = relay.Run(ctx)

		if sleepCalled {
			t.Errorf("Sleep should not have been called for 400")
		}
		dls := relay.DeadLetters()
		if len(dls) != 1 {
			t.Fatalf("expected 1 dead letter, got %d", len(dls))
		}
		if dls[0].Attempts != 1 || dls[0].LastStatus != 400 {
			t.Errorf("expected Attempts=1, LastStatus=400, got %+v", dls[0])
		}
	})

	t.Run("five 500s with MaxAttempts 5 yield Sleep [1s, 2s, 4s, 8s] and dead letter Attempts 5", func(t *testing.T) {
		body := []byte("error-req")
		fake := &fakeDoer{
			handlers: []func(req *http.Request) (*http.Response, error){
				func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 500, Body: io.NopCloser(bytes.NewReader(nil))}, nil
				},
				func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 500, Body: io.NopCloser(bytes.NewReader(nil))}, nil
				},
				func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 500, Body: io.NopCloser(bytes.NewReader(nil))}, nil
				},
				func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 500, Body: io.NopCloser(bytes.NewReader(nil))}, nil
				},
				func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 500, Body: io.NopCloser(bytes.NewReader(nil))}, nil
				},
			},
		}
		var sleepMu sync.Mutex
		var sleepDurations []time.Duration
		fakeSleep := func(ctx context.Context, d time.Duration) error {
			sleepMu.Lock()
			sleepDurations = append(sleepDurations, d)
			sleepMu.Unlock()
			return nil
		}

		relay, err := webhookrelay.New(webhookrelay.Config{
			InboundSecret: inboundSecret,
			TargetURL:     "https://example.com/target",
			QueueSize:     10,
			MaxAttempts:   5,
			BaseBackoff:   1 * time.Second,
			Client:        fake,
			Sleep:         fakeSleep,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set("X-Hub-Signature-256", calcHMAC(inboundSecret, body))
		rec := httptest.NewRecorder()
		relay.ServeHTTP(rec, req)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			for {
				if len(relay.DeadLetters()) == 1 {
					cancel()
					return
				}
				time.Sleep(2 * time.Millisecond)
			}
		}()
		_ = relay.Run(ctx)

		wantSleeps := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
		sleepMu.Lock()
		if len(sleepDurations) != len(wantSleeps) {
			t.Fatalf("expected 4 sleeps, got %v", sleepDurations)
		}
		for i, ws := range wantSleeps {
			if sleepDurations[i] != ws {
				t.Errorf("sleep[%d]: expected %v, got %v", i, ws, sleepDurations[i])
			}
		}
		sleepMu.Unlock()

		dls := relay.DeadLetters()
		if len(dls) != 1 {
			t.Fatalf("expected 1 dead letter, got %d", len(dls))
		}
		if dls[0].Attempts != 5 || dls[0].LastStatus != 500 {
			t.Errorf("expected Attempts=5, LastStatus=500, got %+v", dls[0])
		}
	})

	t.Run("the 101st dead letter evicts the oldest so len(DeadLetters()) == 100", func(t *testing.T) {
		fake := &fakeDoer{
			handlers: make([]func(req *http.Request) (*http.Response, error), 105),
		}
		for i := 0; i < 105; i++ {
			fake.handlers[i] = func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 400, Body: io.NopCloser(bytes.NewReader(nil))}, nil
			}
		}

		relay, err := webhookrelay.New(webhookrelay.Config{
			InboundSecret: inboundSecret,
			TargetURL:     "https://example.com/target",
			QueueSize:     150,
			Client:        fake,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Queue 101 items
		for i := 1; i <= 101; i++ {
			body := []byte(fmt.Sprintf("item-%d", i))
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
			req.Header.Set("X-Hub-Signature-256", calcHMAC(inboundSecret, body))
			rec := httptest.NewRecorder()
			relay.ServeHTTP(rec, req)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("failed to accept item %d: %d", i, rec.Code)
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			for {
				if relay.Stats().DeadLettered == 100 && relay.Stats().Queued == 0 {
					cancel()
					return
				}
				time.Sleep(2 * time.Millisecond)
			}
		}()
		_ = relay.Run(ctx)

		dls := relay.DeadLetters()
		if len(dls) != 100 {
			t.Fatalf("expected 100 dead letters, got %d", len(dls))
		}
		// Oldest item "d-1" was evicted; first remaining is "d-2", last is "d-101"
		if dls[0].ID != "d-2" {
			t.Errorf("expected first dead letter ID to be d-2, got %s", dls[0].ID)
		}
		if dls[99].ID != "d-101" {
			t.Errorf("expected 100th dead letter ID to be d-101, got %s", dls[99].ID)
		}
	})
}

// Acceptance 7: Cancelling ctx while Sleep blocks makes Run return context.Canceled within 1 s
// with the item still queued (Stats().Queued == 1), and no OnEvent payload contains
// "Hello, World!", "out" or the inbound secret
func TestAcceptance7_CancelDuringSleepAndRedaction(t *testing.T) {
	inboundSecretStr := "super-inbound-secret-key"
	inboundSecret := []byte(inboundSecretStr)
	outboundSecretStr := "super-outbound-secret-key"
	outboundSecret := []byte(outboundSecretStr)
	bodyStr := "Hello, World!"
	body := []byte(bodyStr)

	fake := &fakeDoer{
		handlers: []func(req *http.Request) (*http.Response, error){
			func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 500, Body: io.NopCloser(bytes.NewReader(nil))}, nil
			},
		},
	}

	sleepEntered := make(chan struct{})
	fakeSleep := func(ctx context.Context, d time.Duration) error {
		close(sleepEntered)
		<-ctx.Done()
		return ctx.Err()
	}

	var eventsMu sync.Mutex
	var recordedEvents []webhookrelay.Event

	onEvent := func(ev webhookrelay.Event) {
		eventsMu.Lock()
		recordedEvents = append(recordedEvents, ev)
		eventsMu.Unlock()
	}

	relay, err := webhookrelay.New(webhookrelay.Config{
		InboundSecret:  inboundSecret,
		OutboundSecret: outboundSecret,
		TargetURL:      "https://example.com/target",
		QueueSize:      10,
		Client:         fake,
		Sleep:          fakeSleep,
		OnEvent:        onEvent,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", calcHMAC(inboundSecret, body))
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}

	ctx, cancel := context.WithCancel(context.Background())

	runDone := make(chan error, 1)
	go func() {
		runDone <- relay.Run(ctx)
	}()

	<-sleepEntered
	cancel()

	select {
	case runErr := <-runDone:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", runErr)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("Run did not return within 1 second")
	}

	if q := relay.Stats().Queued; q != 1 {
		t.Errorf("expected Stats().Queued == 1, got %d", q)
	}

	eventsMu.Lock()
	defer eventsMu.Unlock()
	for _, ev := range recordedEvents {
		checkFields := []string{ev.Kind, ev.ID, ev.Reason}
		for _, field := range checkFields {
			if strings.Contains(field, bodyStr) {
				t.Errorf("event contained sensitive body payload %q in field %q", bodyStr, field)
			}
			if strings.Contains(field, outboundSecretStr) {
				t.Errorf("event contained outbound secret in field %q", field)
			}
			if strings.Contains(field, inboundSecretStr) {
				t.Errorf("event contained inbound secret in field %q", field)
			}
		}
	}
}

// Acceptance 8: New returns an error matching ErrInvalidConfig (errors.Is) for an empty TargetURL,
// a TargetURL with scheme "ftp", an empty InboundSecret or QueueSize 0
func TestAcceptance8_InvalidConfig(t *testing.T) {
	validSecret := []byte("secret")
	validURL := "https://example.com/target"

	tests := []struct {
		name string
		cfg  webhookrelay.Config
	}{
		{
			name: "empty TargetURL",
			cfg: webhookrelay.Config{
				InboundSecret: validSecret,
				TargetURL:     "",
				QueueSize:     10,
			},
		},
		{
			name: "TargetURL with ftp scheme",
			cfg: webhookrelay.Config{
				InboundSecret: validSecret,
				TargetURL:     "ftp://example.com/target",
				QueueSize:     10,
			},
		},
		{
			name: "empty InboundSecret",
			cfg: webhookrelay.Config{
				InboundSecret: nil,
				TargetURL:     validURL,
				QueueSize:     10,
			},
		},
		{
			name: "QueueSize 0",
			cfg: webhookrelay.Config{
				InboundSecret: validSecret,
				TargetURL:     validURL,
				QueueSize:     0,
			},
		},
		{
			name: "QueueSize over limit",
			cfg: webhookrelay.Config{
				InboundSecret: validSecret,
				TargetURL:     validURL,
				QueueSize:     100001,
			},
		},
		{
			name: "TargetURL invalid parse",
			cfg: webhookrelay.Config{
				InboundSecret: validSecret,
				TargetURL:     "://bad-url",
				QueueSize:     10,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := webhookrelay.New(tc.cfg)
			if !errors.Is(err, webhookrelay.ErrInvalidConfig) {
				t.Fatalf("expected ErrInvalidConfig, got %v", err)
			}
		})
	}
}

// Additional tests for coverage: transport error retries, max backoff ceiling, long error truncation
func TestAdditionalCoverage(t *testing.T) {
	inboundSecret := []byte("in")
	body := []byte("error_test")

	t.Run("network error retried then succeeds", func(t *testing.T) {
		fake := &fakeDoer{
			handlers: []func(req *http.Request) (*http.Response, error){
				func(req *http.Request) (*http.Response, error) {
					return nil, errors.New("dial tcp connection refused")
				},
				func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(nil))}, nil
				},
			},
		}

		fakeSleep := func(ctx context.Context, d time.Duration) error {
			return nil
		}

		relay, err := webhookrelay.New(webhookrelay.Config{
			InboundSecret: inboundSecret,
			TargetURL:     "http://localhost:8080/dest",
			QueueSize:     10,
			Client:        fake,
			Sleep:         fakeSleep,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set("X-Hub-Signature-256", calcHMAC(inboundSecret, body))
		rec := httptest.NewRecorder()
		relay.ServeHTTP(rec, req)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			for {
				if relay.Stats().Delivered == 1 {
					cancel()
					return
				}
				time.Sleep(2 * time.Millisecond)
			}
		}()
		_ = relay.Run(ctx)

		if relay.Stats().Delivered != 1 {
			t.Errorf("expected delivered 1, got %d", relay.Stats().Delivered)
		}
	})

	t.Run("long error message is truncated to 200 bytes", func(t *testing.T) {
		longMsg := strings.Repeat("0123456789", 30) // 300 bytes
		fake := &fakeDoer{
			handlers: []func(req *http.Request) (*http.Response, error){
				func(req *http.Request) (*http.Response, error) {
					return nil, errors.New(longMsg)
				},
			},
		}

		relay, err := webhookrelay.New(webhookrelay.Config{
			InboundSecret: inboundSecret,
			TargetURL:     "http://localhost:8080/dest",
			QueueSize:     10,
			MaxAttempts:   1,
			Client:        fake,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set("X-Hub-Signature-256", calcHMAC(inboundSecret, body))
		rec := httptest.NewRecorder()
		relay.ServeHTTP(rec, req)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			for {
				if len(relay.DeadLetters()) == 1 {
					cancel()
					return
				}
				time.Sleep(2 * time.Millisecond)
			}
		}()
		_ = relay.Run(ctx)

		dls := relay.DeadLetters()
		if len(dls) != 1 {
			t.Fatalf("expected 1 dead letter, got %d", len(dls))
		}
		if len(dls[0].LastError) > 200 {
			t.Errorf("expected LastError <= 200 bytes, got %d", len(dls[0].LastError))
		}
	})

	t.Run("default sleep timer path", func(t *testing.T) {
		relay, err := webhookrelay.New(webhookrelay.Config{
			InboundSecret: inboundSecret,
			TargetURL:     "http://localhost:8080/dest",
			QueueSize:     10,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // already canceled
		err = relay.Run(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	})
}

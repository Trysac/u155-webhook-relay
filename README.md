# webhook-relay

Store-and-forward webhook relay for Go applications with HMAC-SHA256 verification, in-memory queueing, outbound re-signing, exponential backoff, and dead-letter auditing. This package addresses the issue where webhook senders time out during receiver downtime or slow processing, causing event loss. It acts as an http.Handler to accept webhooks quickly after validation, then uses a background worker to deliver them with retries.

## Installation

```bash
go get github.com/Trysac/u155-webhook-relay
```

## Quick Start

```go
package main

import (
	"context"
	"net/http"
	webhookrelay "github.com/Trysac/u155-webhook-relay"
)

func main() {
	relay, _ := webhookrelay.New(webhookrelay.Config{
		InboundSecret: []byte("s"),
		TargetURL:     "https://example.com/dest",
		QueueSize:     100,
	})
	go relay.Run(context.Background())
	http.ListenAndServe(":8080", relay)
}
```

## Public API

- `New(Config) (*Relay, error)`: Initializes the relay. Returns `ErrInvalidConfig` for invalid inputs (empty secrets, empty URL, QueueSize 0).
- `(r *Relay) ServeHTTP(http.ResponseWriter, *http.Request)`: HTTP handler. Verifies HMAC-SHA256, enforces MaxBodyBytes, and queues requests. Returns 202 Accepted, 401 Unauthorized, 405 Method Not Allowed, 413 Payload Too Large, or 503 Service Unavailable.
- `(r *Relay) Run(context.Context) error`: Executes the delivery worker loop. Delivers via FIFO queue.
- `(r *Relay) Stats() Stats`: Returns current Queued, Delivered, and DeadLettered counts.
- `(r *Relay) DeadLetters() []DeadLetter`: Returns the list of last 100 dead-lettered webhooks.

## Why not queue+worker service?

This is a single small package with no external broker or infrastructure dependencies, designed for low-volume webhooks where a full queueing system adds unnecessary complexity.

See [docs/SECURITY.md](docs/SECURITY.md).
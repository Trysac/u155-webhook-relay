# Architecture

`webhookrelay` is a single-process, in-memory store-and-forward HTTP webhook relay designed to decouple external webhook senders from downstream service availability.

## Components

1. **HTTP Handler (`ServeHTTP`)**:
   - Enforces HTTP method restrictions (POST only).
   - Protects against resource exhaustion using `MaxBodyBytes` and `io.LimitReader`.
   - Validates inbound SHA256 HMAC headers in constant time (`hmac.Equal`).
   - Enqueues valid requests into a bounded memory buffer or rejects with HTTP 503 if full.
   - Responds immediately with HTTP 202 Accepted and a unique delivery ID (`{"id":"d-N"}`).

2. **Delivery Worker (`Run`)**:
   - Sequential FIFO delivery loop.
   - For each queued item, prepares outbound requests with:
     - Content-Type preserved from inbound request.
     - `X-Relay-Delivery`: delivery ID.
     - `X-Relay-Attempt`: sequential attempt counter starting at 1.
     - `X-Relay-Signature`: HMAC-SHA256 signed using configured outbound secret.
   - Handles HTTP 2xx as success, removing the item from the queue.
   - Handles retryable errors (network failures, HTTP 408, 429, 5xx) with exponential backoff (`BaseBackoff << (attempt - 1)` up to `MaxBackoff`) and `Retry-After` support.
   - Non-retryable errors (4xx other than 408/429) or exceeded max attempts are converted into a `DeadLetter` entry.
   - Items remain in the queue across transient pauses and cancellation.

3. **Dead-Letter Storage & Stats**:
   - Ring buffer retaining up to 100 dead letters, evicting the oldest on overflow.
   - Error messages are strictly truncated to 200 bytes on rune boundaries, stripping sensitive webhook payload data.
   - Concurrent-safe inspection via `Stats()` and `DeadLetters()`.

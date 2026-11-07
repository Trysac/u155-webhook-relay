# In-memory store-and-forward relay design

Status: accepted (generated, pending human review)

## Context

External webhook senders often timeout or drop webhooks if downstreams are restarting or slow. Introducing heavy external message brokers increases operational complexity for low-to-medium volume webhooks. A lightweight, embedded in-memory relay ensures fast acknowledgement, signature verification, and delivery retries with zero external runtime dependencies.

## Decision

Implement the relay as a standard http.Handler coupled with a sequential Run delivery worker. Enforce strict memory bounds on queue size, body length, and dead-letter history. Maintain items in the queue until confirmed delivered or dead-lettered so caller context cancellations never drop queued items silently.

## Consequences

In-memory queueing does not survive unexpected process crashes, which is explicitly accepted for this single-process relay scope. Retries, backoff, and signature verification are handled cleanly in standard library Go without third-party dependencies.

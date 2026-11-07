# Security notes

## Threat model

This library implements a relay, not a generic proxy. Defenses include:

- **Inbound Verification**: Enforces HMAC-SHA256 validation on all incoming requests using the provided `InboundSecret`. Rejects invalid signatures with 401 Unauthorized.
- **Resource Exhaustion**: Uses `http.MaxBytesReader` to enforce `MaxBodyBytes` (default 1MiB) to prevent memory exhaustion attacks.
- **Secrets Handling**: `OnEvent` callbacks and internal logging are designed to prevent leaking the inbound secret, outbound secret, or webhook payloads in error messages. Dead-letter error messages are truncated to 200 bytes.

## Not defended

- **Replay attacks**: The relay does not track or store nonces/timestamps for replay prevention.
- **Persistence**: Data is held in-memory; a process crash results in data loss.
- **External system security**: Assumes the `TargetURL` provided is trusted by the administrator.
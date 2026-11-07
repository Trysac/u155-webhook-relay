# Project record

## Objective

Store-and-forward webhook relay: verify an inbound HMAC-SHA256 signature, queue in bounded memory and deliver with re-signing, exponential backoff and a dead-letter list.

## Scope

- In scope: Inbound HMAC-SHA256 verification (X-Hub-Signature-256), bounded in-memory queueing, outbound re-signing, exponential backoff (no jitter), dead-letter storage (max 100), and event callbacks.
- Out of scope: Persistence across restarts, replay protection, multiple targets, fan-out, metrics endpoints, jitter, and any logic requiring dependencies or I/O outside standard library.

## Effort metrics

| Metric | Value |
|---|---|
| Tokens (input / output) | 44230 / 22497 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.0514 |

## Factory run u155 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | gemini-3.8-flash | yes | 4416 | 20918 | 0 | 0 | 0.0409 |
| audit | gemini-3.1-flash-lite | no | 27323 | 276 | 0 | 8162 | 0.0074 |
| docs | gemini-3.1-flash-lite | no | 4329 | 1303 | 0 | 0 | 0.0030 |

Total: $0.0514. Prices: Anthropic list prices.

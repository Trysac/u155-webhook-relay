// Package webhookrelay is a small, dependency-free Go library: Store-and-forward webhook relay: verify an inbound HMAC-SHA256 signature, queue in bounded memory and deliver with re-signing, exponential backoff and a dead-letter list
//
// The public API is every exported identifier of this root package. Functions are pure: they do
// no I/O, keep no global mutable state and report invalid input through returned errors.
package webhookrelay

# webhook-relay

[![Go Reference](https://pkg.go.dev/badge/github.com/Trysac/u155-webhook-relay.svg)](https://pkg.go.dev/github.com/Trysac/u155-webhook-relay)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Trysac/u155-webhook-relay/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u155-webhook-relay/actions/workflows/ci.yml)

Store-and-forward webhook relay: verify an inbound HMAC-SHA256 signature, queue in bounded memory and deliver with re-signing, exponential backoff and a dead-letter list

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
go get github.com/Trysac/u155-webhook-relay
```

Requires Go 1.23 or newer. No dependencies outside the standard library.

## Usage

```go
package main

import (
	"errors"
	"fmt"

	"github.com/Trysac/u155-webhook-relay"
)

func main() {
	// Normalize trims surrounding whitespace and lower-cases the text.
	out, _ := webhookrelay.Normalize("  Hello World ")
	fmt.Println(out) // -> "hello world"

	// Blank input is rejected explicitly instead of returning an empty string.
	if _, err := webhookrelay.Normalize("   "); errors.Is(err, webhookrelay.ErrBlank) {
		fmt.Println("rejected:", err)
	}
}
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez

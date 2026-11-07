# Testing

## Running

```sh
go test -race -cover . 
```

## Coverage

- Tests cover the public API using table-driven tests with subtests (`t.Run`).
- Every observable effect is asserted, including return values, status codes, and error types using `errors.Is`.
- Examples are used to document usage, with `// Output:` comments verified by `go test`.

## Test Files

- `relay_test.go`: Exercises the full lifecycle (ServeHTTP -> queue -> Run delivery -> DeadLetter/Success) using a fake Doer to inject network errors (500, 429) and a fake Sleep function to verify backoff timing without waiting real time.
- Fixtures and golden files are stored in `testdata/`.
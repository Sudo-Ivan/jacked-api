# Benchmarks

## Running Benchmarks Locally

To run benchmarks locally:

```bash
go test -bench=. -benchmem -count=6 ./...
```

## Benchmark Results

Benchmark results are automatically generated and compared in our CI pipeline. The results are stored in the `benchmarks/` directory.

### Understanding the Results

- `-bench=.` runs all benchmarks
- `-benchmem` includes memory allocation statistics
- `-count=6` runs each benchmark 6 times for more accurate results
# Performance evidence

Run benchmarks on the same idle machine, with the same Go toolchain and power
settings. The scripts default to `GOMAXPROCS=10`, ten samples, one second per
sample, and store raw results below the ignored `.cache/perf` directory.

```sh
GOEXPERIMENT=nojsonv2 scripts/perf/run_benchmarks.sh base
GOEXPERIMENT=nojsonv2 scripts/perf/run_benchmarks.sh head
scripts/perf/compare_benchmarks.sh .cache/perf/base.bench.txt .cache/perf/head.bench.txt
GOEXPERIMENT=nojsonv2 scripts/perf/measure_binaries.sh head
```

These commands select the release JSON runtime explicitly. Set
`GOEXPERIMENT=` instead when measuring the Go 1.27 default JSON runtime.

If a result crosses a merge threshold without a statistically clear result,
repeat both sides with `BENCH_COUNT=20`. Generate CPU and heap profiles for a
single representative benchmark with:

```sh
GOEXPERIMENT=nojsonv2 scripts/perf/profile_benchmark.sh ./trace BenchmarkMTRAggregatorSnapshot64TTL4Paths profile-name
```

Record `go version`, `go env GOEXPERIMENT`, the exact commit IDs, machine,
operating system, `GOMAXPROCS`, sample count, and any profiler or UPX version in
the pull request. Keep raw profiles and binaries as CI artifacts rather than
committing them.

`measure_binaries.sh` records stripped local-platform sizes. Set `UPX_BIN` to an
exact UPX executable when that target format is supported; use the same binary
and flags for both sides of a comparison.

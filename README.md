# CenKL

`CenKL` is a command-line tool for analysing and modelling network traffic. It ingests raw Zeek logs, extracts per-packet features, builds statistical traffic models, and can generate synthetic flows that mimic real traffic patterns.

## Typical workflow

```
Zeek logs → zeek2flows → binary flows file
                               ↓
                          stats compute → TrafficStats
                               ↓
                          stats bin → ModelAssumptions (quantizer)
                               ↓
                    pipeline histograms → TrafficProfile (the model)
                               ↓
                    generate / dump-csv → synthetic or exported flows
```

---

## Commands

### `zeek2flows`
Parses raw Zeek conn and packets logs and writes a compact binary flows file used by all other commands.

```
obfs zeek2flows --flows <path> --packets <path> --output <path>
```

| Flag | Description |
|---|---|
| `--flows` | Path to the Zeek conn log (flow metadata) |
| `--packets` | Path to the Zeek packets log (per-packet features) |
| `--output` | Output path for the binary flows file |

---

### `stats compute`
Scans a flows file and collects per-packet feature statistics (min, max, quantile sketches). The output is used by `stats bin` to build a quantizer.

```
obfs stats compute --flows <path> --output <path> [options]
```

| Flag | Default | Description |
|---|---|---|
| `--flows` | | Path to a binary flows file |
| `--output` | | Output path for the stats file |
| `--flow-filter` | `tlsDataPackets >= 0` | Only include flows matching this predicate (see [Flow filters](#flow-filters)) |
| `--strip-tls-handshake` | false | Exclude TLS handshake packets before computing stats |

### `stats merge`
Merges multiple stats files (e.g. computed in parallel over shards) into one.

```
obfs stats merge --input <dir> --output <path>
```

| Flag | Description |
|---|---|
| `--input` | Directory containing TrafficStats files to merge |
| `--output` | Output path for the merged stats file |

### `stats bin`
Converts a stats file into a quantizer — the binning scheme that maps continuous feature values to discrete bins. The output (`ModelAssumptions` JSON) is required by `pipeline histograms`, `dump-csv`, and `generate`.

```
obfs stats bin --input <path> --output <path> [options]
```

| Flag | Default | Description |
|---|---|---|
| `--input` | | Path to a TrafficStats file |
| `--output` | | Output path for the ModelAssumptions JSON |
| `--markov-order` | `0` | Order of the Markov chain (0 = each packet is independent; higher values capture dependencies between consecutive packets) |
| `--epsilon` | `0.05` | Accuracy of quantile estimation — lower is more accurate but produces more bins |
| `--delta` | `0.05` | Maximum probability mass allowed per bin — lower forces finer granularity |
| `--mask` | | Features to exclude entirely (e.g. `--mask timestamp`) |

### `stats display`
Prints a human-readable summary of a stats file, useful for inspecting feature distributions.

```
obfs stats display --input <path> [options]
```

| Flag | Description |
|---|---|
| `--input` | Path to a TrafficStats file |
| `--feature` | Narrow output to one feature (`Timestamp`, `Direction`, or `Size`) |
| `--index` | Narrow output to a specific packet index |

---

### `pipeline histograms`
End-to-end pipeline: loads flows, quantizes them using the model assumptions, and fits a Markov-chain traffic model (TrafficProfile). The config is a TOML file; `--flows` overrides the path set in the config.

```
obfs pipeline histograms --config <path> --output <path> [--flows <path>]
```

| Flag | Description |
|---|---|
| `--config` | Path to a TOML pipeline config file (see [Pipeline config](#pipeline-config)) |
| `--output` | Output path for the TrafficProfile |
| `--flows` | Override the flow source path from the config |

#### Pipeline config

The TOML config file has two sections:

```toml
[flow]
strip_tls_handshake = true   # whether to exclude handshake packets

[flow.source_a]
# Option 1: load from a flows file
Empirical = { path = "path/to/flows", flow_filter = "tlsDataPackets >= 10" }

# Option 2: generate synthetic flows from an existing model
Generated = { traffic_profile = "model.bin", quantizer = "model.json", num_flows = 10000, flow_length = 20 }

[model]
model_assumptions = "model.json"   # path to the quantizer produced by stats bin
pseudocount = 1.0                  # smoothing added to each histogram bin (default: 1.0)
```

---

### `generate`
Samples synthetic flows from a saved TrafficProfile by ancestral sampling through the Markov chain. Outputs a CSV of per-packet features.

```
obfs generate --traffic-profile <path> --model <path> --num-flows <N> --flow-length <N> [options]
```

| Flag | Default | Description |
|---|---|---|
| `--traffic-profile` | | Path to a TrafficProfile file produced by `pipeline histograms` |
| `--model` | | Path to the ModelAssumptions JSON (quantizer) |
| `--num-flows` | | Number of flows to generate |
| `--flow-length` | | Number of packets per flow |
| `--output` | stdout | CSV output path |
| `--quantized` | false | Emit raw bin indices instead of dequantized feature values |
| `--seed` | | Fix the random seed for reproducible output |

---

### `dump-csv`
Exports a binary flows file to a flat CSV where each row is a flow and columns are per-packet features. Useful for loading traffic data into Python/pandas for external analysis.

```
obfs dump-csv --flows <path>... --model-assumptions <path> -N <n> --output <path> [options]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--flows` | | | One or more binary flows files |
| `--model-assumptions` | | | Path to the ModelAssumptions JSON (quantizer) |
| `--max-packets` | `-N` | | Maximum packets per flow to emit (determines number of columns) |
| `--output` | | | Output CSV path |
| `--num-flows` | `-M` | unlimited | Stop after writing this many rows |
| `--min-packets` | | `--max-packets` | Skip flows shorter than this |
| `--strip-tls-handshake` | | false | Exclude handshake packets before emitting features |
| `--flow-filter` | | `tlsDataPackets >= 0` | Only include flows matching this predicate |
| `--skip-timing` | | false | Omit timestamp columns (emit only size and direction) |
| `--quantized` | | false | Emit bin indices instead of raw feature values |
| `--include-rtt` | | false | Prepend the flow's round-trip time (seconds) as the first column |

---

### `histograms display`
Prints the histogram at a given packet index from a saved TrafficProfile.

```
obfs histograms display --input <path> --index <n> [options]
```

| Flag | Description |
|---|---|
| `--input` | Path to a TrafficProfile file |
| `--index` | Packet index to display |
| `--min-count` | Hide bins with fewer than this many observations |
| `--min-probability` | Hide bins with probability below this threshold |
| `--top-k` | Show only the K most probable bins |
| `--model` | ModelAssumptions JSON; if provided, bin indices are decoded to human-readable value ranges |

### `histograms merge`
Merges multiple TrafficProfile files (e.g. built over shards) into one.

```
obfs histograms merge --input <dir> --output <path>
```

### `histograms divergence`
Computes the per-packet KL divergence between two TrafficProfiles. The result is written to disk and consumed by the `divergence` subcommands.

```
obfs histograms divergence --left <path> --right <path> --output <path>
```

| Flag | Description |
|---|---|
| `--left` | Reference TrafficProfile |
| `--right` | Comparison TrafficProfile |
| `--output` | Output path for the KL divergence file |

---

### `divergence cumulative`
Prints the cumulative KL divergence summed from packet 0 to each index.

```
obfs divergence cumulative --input <path>
```

### `divergence delta`
Prints the per-packet increment in KL divergence (i.e. how much each individual packet position contributes).

```
obfs divergence delta --input <path>
```

### `divergence terms`
For a given packet index, lists the individual histogram bins that contribute most to the KL divergence at that position.

```
obfs divergence terms --input <path> --index <n>
```

---

## Flow filters

The `--flow-filter` flag accepts a simple predicate language:

| Predicate | Example | Meaning |
|---|---|---|
| `tlsDataPackets >= N` | `tlsDataPackets >= 10` | Only flows with at least N post-handshake packets |
| `tlsVersion == V` | `tlsVersion == TLSv13` | Only flows matching a TLS version (`TLSv12` or `TLSv13`) |

Combine predicates with `&&`:
```
"tlsDataPackets >= 10 && tlsVersion == TLSv13"
```

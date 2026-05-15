# Source Overview

`obfs` is a command-line tool for analysing and modelling network traffic. It ingests raw Zeek logs, extracts per-packet features, builds statistical traffic models, and can generate synthetic flows that mimic real traffic patterns.

## How it fits together

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

## Modules

### `main.rs`
- Loading and preprocessing flows (RTT normalisation, stripping TLS handshake packets)
- Building and serialising traffic models (histograms)
- Emitting feature vectors to CSV

### `cli.rs`
Defines every command-line argument and subcommand.

**Subcommands:**
| Subcommand | What it does |
|---|---|
| `zeek2flows` | Converts raw Zeek conn + packets logs into a compact binary flows file used by other commands |
| `stats compute` | Scans a flows file and collects per-packet statistics (min, max, quantile sketches) needed to build a quantizer |
| `stats merge` | Merges multiple stats files into one (useful when stats are computed in parallel over shards) |
| `stats bin` | Turns a stats file into a quantizer — the binning scheme that maps continuous feature values to discrete histogram bins |
| `stats display` | Prints a human-readable summary of a stats file |
| `pipeline histograms` | Full pipeline: loads flows, fits a Markov-chain traffic model, and writes it to disk |
| `generate` | Samples synthetic flows from a saved traffic model |
| `dump-csv` | Exports a binary flows file to a flat CSV of per-packet features |
| `histograms display` | Prints the histogram at a given packet index from a saved model |
| `histograms merge` | Merges histogram files from multiple shards |
| `histograms divergence` | Computes per-packet KL divergence between two traffic profiles |
| `divergence cumulative` | Shows the cumulative KL divergence as packet index increases |
| `divergence delta` | Shows the per-packet increment in KL divergence |
| `divergence terms` | Identifies the individual histogram bins contributing most to divergence at a given packet index |

**Flow filters** (`--flow-filter`) let you restrict which flows are processed:
- `tlsDataPackets >= N` — only flows with at least N packets after the TLS handshake
- `tlsVersion == TLSv12` or `TLSv13` — only flows of a specific TLS version
- Combine conditions with `&&`

### `base.rs`
The core data model. Defines what a flow and a packet look like in memory, and handles reading/writing the binary flows file format.

A **flow** is a single TCP connection: it has connection metadata (timestamps for SYN/SYN-ACK/ACK, connection ID) and an ordered list of packets. Each **packet** has three features: the time since the previous packet (timestamp), whether it was sent by the client or server (direction), and payload size.

Also defines `FlowFilterPredicate`, the runtime representation of the `--flow-filter` argument, and the Zeek log parser (`zeek2flows`).

### `feature.rs`
Defines the three observable packet features (`Timestamp`, `Direction`, `Size`). Also defines:
- `EmitFeatures`: implemented by `Flow`. allows you to iterate through a flow's packets and extract their feature values one by one.
- `FeatureEmitter`: the target that receives those feature values (e.g. a CSV writer, a statistics accumulator, etc.)

Think of it as: `Flow` → `EmitFeatures` → pushes values to → `FeatureEmitter` (like a CSV writer).

### `quantization.rs`
Handles discretisation: turning continuous feature values (e.g. a packet size of 512 bytes) into discrete bins (e.g. bin 6) so they can be used as histogram keys.

- A **`FeatureQuantizer`** bins one feature (e.g. size) using one of several strategies: uniform buckets, log-uniform buckets, t-digest-derived quantile buckets, or masked out entirely.
- A **`PacketQuantizer`** combines a quantizer for each feature into a single per-packet discretiser.
- A **`FlowQuantizer`** is either one global `PacketQuantizer` applied to every packet, or a separate one per packet index (useful when feature distributions shift significantly across packet position).
- **`PacketProjection`** is the result of quantizing a packet — a tuple of bin indices, one per active feature, used as the key in a histogram.

### `stats.rs`
Before you can build a quantizer, you need to know the distribution of each feature across your dataset. `TrafficStats` accumulates this information by scanning flows. For each packet index it maintains a t-digest (for quantile estimation) and min/max bounds for each feature. `TrafficStats::from_flows` does this in parallel. Once computed, stats are saved to disk and fed into `stats bin` to produce the quantizer.

### `histograms.rs`
The traffic model itself. After flows are quantized, each flow becomes a sequence of `PacketProjection` tuples. A **`TrafficProfile`** is a Markov chain over this sequence: for each packet position it stores a histogram counting how often each `PacketProjection` (or short sequence of projections, for higher-order Markov models) was observed. This lets the model capture dependencies between consecutive packets.

`TrafficProfile::kl_divergence` measures how different two profiles are, packet by packet, using KL divergence — useful for evaluating whether two traffic sources are statistically distinguishable.

### `generator.rs`
Given a saved `TrafficProfile`, generates synthetic flows by sampling. For each packet position, it samples the next `PacketProjection` from the conditional distribution given recent history (if markov order > 0), then dequantizes it back to continuous feature values. The result is a `Flow` that statistically resembles the training data.

### `divergence.rs`
Post-processing for KL divergence results produced by `histograms divergence`. `KLDivergence` wraps the per-packet divergence array and exposes views useful for analysis: cumulative sum, per-packet increment, and the individual histogram terms that contribute most at a given index.

### `merge.rs`
A small utility for combining results computed in parallel over data shards. Any type that implements `Merge` (e.g. `TrafficStats`, `TrafficProfile`) can be reduced across a directory of files into a single merged result.

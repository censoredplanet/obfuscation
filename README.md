# Source Overview

This document describes the modules that make up the `obfs` binary.

## Modules

### `main.rs`
Entry point and orchestration. Parses the CLI, dispatches subcommands, and contains shared utilities used across pipelines:
- `ModelAssumptions` — serializable struct pairing a Markov order with a `FlowQuantizer`.
- `CsvEmitter` — low-allocation CSV row builder used by the dump-csv and generate commands.
- `FeatureEncoding` — enum selecting raw vs. quantized feature output.
- `write_json` — helper to serialise any `serde::Serialize` value to a pretty-printed JSON file.
- `read_and_filter_flows` / `materialize_sources` — load and optionally clone flow sets from `FlowSource` descriptors.
- `prepare_flows` — loads and preprocesses (RTT-normalise, strip-handshake) a flow source for a pipeline run.
- `build_and_write_histograms` — builds a `TrafficProfile` from a flow set and writes it to disk.
- `run_histograms_pipeline` — end-to-end histogram pipeline (load → preprocess → histogram → write).

### `cli.rs`
All CLI argument structs, pipeline configuration structs, and the flow-filter DSL parser.

**Top-level subcommands:**
| Subcommand | Description |
|---|---|
| `zeek2flows` | Parse Zeek conn + packets logs into a binary flows file |
| `stats` | Compute, merge, bin, or display `TrafficStats` |
| `pipeline histograms` | Run the histogram pipeline from a TOML config |
| `generate` | Sample synthetic flows from a `TrafficProfile` |
| `dump-csv` | Export a binary flows file to a feature CSV |
| `histograms` | Display, merge, or compute divergence of histogram files |
| `divergence` | Analyse a pre-computed KL divergence file |

**Pipeline config structs** (`PipelineConfig`, `FlowConfig`, `Model`) are deserialised from TOML and drive the `pipeline` subcommands.

**Flow-filter DSL** — simple predicate language used with `--flow-filter`:
- `tlsDataPackets >= N` — keep flows with at least N post-handshake packets
- `tlsVersion == TLSv12 | TLSv13` — keep flows matching a TLS version
- Predicates can be combined with `&&`

### `base.rs`
Core data types and I/O:
- `Flow` / `Packet` / `FlowBase` — the in-memory flow representation.
- `ProtocolMetadata` — protocol tag (TLS with handshake boundary, or raw).
- `FlowFilterPredicate` — runtime predicate evaluated against a flow.
- `TLSVersion` — enum for TLS 1.2 / 1.3.
- `stream_flows` / `read_flows` — streaming and batch flow readers.
- `to_key` — derives a `u64` connection key from a raw connection-id byte slice.
- `EmitFeatures` / `FlowFile` traits — implemented by types that can emit feature vectors or be serialised to/from disk.

### `feature.rs`
Feature definitions and emission:
- `FeatureKind` — enum over the observable features (Timestamp, Direction, Size).
- `FeatureValueType` — continuous vs. discrete distinction used during quantization sampling.
- `RandomVariableDomain` — `[min, max]` bounds for a feature.
- `FeatureEmitter` — trait implemented by anything that can receive a stream of feature values (e.g., `CsvEmitter`).
- `EmitFeatures` — trait for types (e.g., `Flow`) that can push their features into a `FeatureEmitter`.
- `PacketProjection` — a quantized per-packet feature vector used as a histogram key.

### `quantization.rs`
Quantizer construction and feature binning:
- `Quantization` — per-feature binning strategy (Uniform, LogUniform, TDigest, or Mask).
- `PacketQuantizer` — per-packet quantizer combining timestamp, direction, and size quantizers.
- `FlowQuantizer` — either a single global `PacketQuantizer` or one per packet index.
- `bin` — constructs a `FlowQuantizer` from a `TrafficStats` using t-digest quantile estimation.

### `stats.rs`
Online traffic statistics used to fit the quantizer:
- `TrafficStats` — per-packet-index accumulators (t-digests, min/max) for all features.
- `TrafficStats::from_flows` — computes stats from a slice of flows in parallel.
- `StatsView` — formatted display of stats, optionally filtered to one feature or packet index.

### `histograms.rs`
Markov-chain traffic model:
- `Histogram<K>` — a map from key `K` to count, with probability and entropy helpers.
- `TrafficProfile` — a per-packet-index sequence of `Histogram<PacketProjection>` representing the traffic model.
- `as_histogram` — accumulates quantized flow packets into a `TrafficProfile`.
- `TrafficProfile::kl_divergence` — computes per-packet KL divergence between two profiles.
- `WeightedSampler` — discrete distribution sampler built from a histogram, used by `generate`.

### `generator.rs`
Synthetic flow generation:
- `generate_flows` — samples `num_flows` flows of `flow_length` packets each by ancestral sampling through the Markov chain defined by a `TrafficProfile`.
- `PacketSource` — trait for streaming packet producers (future use).

### `divergence.rs`
Post-hoc analysis of KL divergence results:
- `KLDivergence` — per-packet divergence values with helpers for cumulative sum, per-index delta, and worst-case term identification.

### `merge.rs`
Directory-level merge utility:
- `merge_from_directory<T>` — reads all files in a directory as type `T` (which must implement `Merge`) and folds them into a single value.

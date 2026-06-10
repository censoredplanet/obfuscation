use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use winnow::Parser as WinnowParser;
use winnow::ascii::{digit1, space0};
use winnow::combinator::{alt, opt, seq};
use winnow::token::literal;

use crate::base::{FlowFilterPredicate, TLSVersion};
use crate::feature::FeatureKind;

#[derive(Debug, Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(name = "zeek2flows")]
    Zeek2Flows(Zeek2FlowsArgs),
    Stats(StatsCli),
    Pipeline(PipelineCli),
    Generate(GenerateArgs),
    #[command(name = "dump-csv")]
    DumpCsv(DumpCsvArgs),
    Histograms(HistogramsCli),
    Divergence(DivergenceCli),
}

#[derive(Debug, Args)]
pub struct Zeek2FlowsArgs {
    /// Zeek log containing flow metadata
    #[arg(long)]
    pub flows: String,
    /// Zeek log containing packet features
    #[arg(long)]
    pub packets: String,
    /// Output path for the binary flows file
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Debug, Parser)]
pub struct StatsCli {
    #[command(subcommand)]
    pub command: StatsCommand,
}

#[derive(Debug, Subcommand)]
pub enum StatsCommand {
    Compute(StatsComputeArgs),
    Merge(StatsMergeArgs),
    Bin(StatsBinArgs),
    Display(StatsDisplayArgs),
}

#[derive(Debug, Args)]
pub struct StatsComputeArgs {
    /// Path to flows
    #[arg(long)]
    pub flows: PathBuf,
    #[arg(long, default_value = "tlsDataPackets >= 0")]
    // this is hack for always true, make this better
    pub flow_filter: FlowFilterPredicate,
    /// Strip TLS handshake packets before computing statistics
    #[arg(long)]
    pub strip_tls_handshake: bool,
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Debug, Args)]
pub struct StatsMergeArgs {
    /// Path to a directory containing TrafficStats files
    #[arg(long)]
    pub input: PathBuf,
    /// Path to the merged TrafficStats file
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Debug, Args)]
pub struct StatsBinArgs {
    /// Path to a TrafficStats file
    #[arg(long)]
    pub input: PathBuf,
    /// Output path for the quantizer (model assumptions JSON)
    #[arg(long)]
    pub output: PathBuf,
    /// Order of the Markov chain used in the traffic model (0 = i.i.d.)
    #[arg(long, default_value_t = 0)]
    pub markov_order: u32,
    /// Approximation error bound for quantile estimation (t-digest epsilon)
    #[arg(long, default_value_t = 0.05)]
    pub epsilon: f64,
    /// Maximum allowed probability mass per quantization bin
    #[arg(long, default_value_t = 0.05)]
    pub delta: f64,
    /// Maximum number of packet positions to include in the quantizer/model
    #[arg(long)]
    pub max_packets: Option<usize>,
    /// Features to mask out (exclude) from the quantizer
    #[arg(long)]
    pub mask: Option<Vec<FeatureKind>>,
}

#[derive(Debug, Args)]
pub struct StatsDisplayArgs {
    /// Path to a TrafficStats file
    #[arg(long)]
    pub input: PathBuf,
    /// Narrow the display to a specific feature kind (e.g. Size, Timestamp)
    #[arg(long)]
    pub feature: Option<FeatureKind>,
    /// Narrow the display to the stats for a specific packet index
    #[arg(long)]
    pub index: Option<usize>,
}

#[derive(Debug, serde::Deserialize, Clone)]
pub enum FlowSource {
    Empirical {
        path: Option<PathBuf>,
        flow_filter: FlowFilterPredicate,
    },
    Generated {
        traffic_profile: PathBuf,
        quantizer: PathBuf,
        num_flows: usize,
        flow_length: usize,
    },
    Clone {
        source: String,
    },
}

fn default_pseudocount() -> f64 {
    1.0
}

#[derive(Debug, serde::Deserialize)]
pub struct Model {
    pub model_assumptions: PathBuf,
    #[serde(default = "default_pseudocount")]
    pub pseudocount: f64,
}

#[derive(Debug, serde::Deserialize)]
pub struct PipelineConfig {
    pub flow: FlowConfig,
    pub model: Model,
}

#[derive(Debug, serde::Deserialize)]
pub struct FlowConfig {
    pub source_a: FlowSource,
    pub strip_tls_handshake: bool,
}


#[derive(Debug, Parser)]
pub struct PipelineCli {
    #[command(subcommand)]
    pub command: PipelineCommand,
}

#[derive(Debug, Subcommand)]
pub enum PipelineCommand {
    Histograms(PipelineHistogramsArgs),
}

#[derive(Debug, Args)]
pub struct CommonPipelineArgs {
    /// Path to a TOML pipeline configuration file
    #[arg(long)]
    pub config: PathBuf,
    /// Override the flow source path from the config file
    #[arg(long)]
    pub flows: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct PipelineHistogramsArgs {
    #[command(flatten)]
    pub common: CommonPipelineArgs,
    /// Output path for histograms
    #[arg(long)]
    pub output: PathBuf,
}


#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// Path to a serialized TrafficProfile (histogram model)
    #[arg(long)]
    pub traffic_profile: PathBuf,
    /// Path to a model assumptions JSON file (provides the quantizer)
    #[arg(long)]
    pub model: PathBuf,
    /// Number of synthetic flows to generate
    #[arg(long)]
    pub num_flows: usize,
    /// Number of packets per generated flow
    #[arg(long)]
    pub flow_length: usize,
    /// Output CSV path; writes to stdout if omitted
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Emit quantized bin ids instead of raw feature values
    #[arg(long)]
    pub quantized: bool,
    /// Optional seed for reproducible generation
    #[arg(long)]
    pub seed: Option<u64>,
}

#[derive(Debug, Args)]
pub struct DumpCsvArgs {
    /// One or more binary flows files (output of zeek2flows); accepts multiple paths
    #[arg(long, num_args = 1..)]
    pub flows: Vec<PathBuf>,
    /// Model assumptions JSON (provides the quantizer / feature mask).
    /// Optional when not using --quantized; omitting emits all features unmasked.
    #[arg(long)]
    pub model_assumptions: Option<PathBuf>,
    /// Max packets per flow (N)
    #[arg(long, short = 'N')]
    pub max_packets: usize,
    /// Maximum number of flow rows to write
    #[arg(long, short = 'M', default_value_t = usize::MAX)]
    pub num_flows: usize,
    /// Minimum packets a flow must have to be included (default = 0, i.e. all flows)
    #[arg(long)]
    pub min_packets: Option<usize>,
    #[arg(long)]
    pub strip_tls_handshake: bool,
    /// Filter flows using the predicate DSL (e.g. "tlsVersion == TLSv13")
    #[arg(long, default_value = "tlsDataPackets >= 0")]
    pub flow_filter: FlowFilterPredicate,
    /// Exclude timing columns from output (emit only size/direction)
    #[arg(long)]
    pub skip_timing: bool,
    /// Emit quantized bin ids instead of raw feature values
    #[arg(long)]
    pub quantized: bool,
    /// Prepend the RTT (in seconds) as the first column and emit raw IAT seconds.
    /// Without this flag, timing columns remain RTT-normalized.
    #[arg(long)]
    pub include_rtt: bool,
    /// Fraction of matching flows to sample from each file (0.0–1.0). Default 1.0 = take all.
    #[arg(long, default_value_t = 1.0)]
    pub sample_rate: f64,
    /// RNG seed for reproducible file shuffling and flow sampling. Omit for random.
    #[arg(long)]
    pub seed: Option<u64>,
    /// Output CSV path
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Debug, Parser)]
pub struct HistogramsCli {
    #[command(subcommand)]
    pub command: HistogramsCommands,
}

#[derive(Debug, Subcommand)]
pub enum HistogramsCommands {
    Display(HistogramsDisplayArgs),
    Divergence(HistogramsDivergenceArgs),
    Merge(HistogramsMergeArgs),
}

#[derive(Debug, Args)]
pub struct HistogramsDisplayArgs {
    /// Path to a serialized TrafficProfile (histograms) file
    #[arg(short, long)]
    pub input: String,
    /// Packet index whose histogram to display
    #[arg(long)]
    pub index: usize,
    /// Hide bins with fewer than this many observations
    #[arg(long)]
    pub min_count: Option<usize>,
    /// Hide bins with probability below this threshold
    #[arg(long)]
    pub min_probability: Option<f64>,
    /// Show only the top-K most probable bins
    #[arg(long)]
    pub top_k: Option<usize>,
    /// Model assumptions JSON; when provided, bin ids are decoded to human-readable values
    #[arg(long)]
    pub model: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct HistogramsMergeArgs {
    /// Directory containing TrafficProfile files to merge
    #[arg(short, long)]
    pub input: PathBuf,
    /// Output path for the merged TrafficProfile file
    #[arg(short, long)]
    pub output: PathBuf,
}

#[derive(Debug, Args)]
pub struct HistogramsDivergenceArgs {
    /// Path to the reference TrafficProfile (left-hand side of KL divergence)
    #[arg(long)]
    pub left: PathBuf,
    /// Path to the comparison TrafficProfile (right-hand side of KL divergence)
    #[arg(long)]
    pub right: PathBuf,
    /// Output path for the per-packet KL divergence file
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Debug, Parser)]
pub struct DivergenceCli {
    #[command(subcommand)]
    pub command: DivergenceCommands,
}

#[derive(Debug, Subcommand)]
pub enum DivergenceCommands {
    Cumulative(DivergenceCumulativeArgs),
    Delta(DivergenceDeltaArgs),
    Terms(DivergenceTermsArgs),
}

#[derive(Debug, Args)]
pub struct DivergenceCumulativeArgs {
    /// Path to a KL divergence file produced by `histograms divergence`
    #[arg(long)]
    pub input: PathBuf,
}

#[derive(Debug, Args)]
pub struct DivergenceDeltaArgs {
    /// Path to a KL divergence file produced by `histograms divergence`
    #[arg(long)]
    pub input: PathBuf,
}

#[derive(Debug, Args)]
pub struct DivergenceTermsArgs {
    /// Path to a KL divergence file produced by `histograms divergence`
    #[arg(long)]
    pub input: PathBuf,
    /// Packet index to inspect for maximum-divergence terms
    #[arg(long)]
    pub index: usize,
}

// ===============
// Flow Filter DSL
// ===============
impl std::str::FromStr for FlowFilterPredicate {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut input = s;

        let predicate = parse_flow_filter_predicate
            .parse_next(&mut input)
            .map_err(|e| format!("Bad flow predicate! {e:?}"))?;

        Ok(predicate)
    }
}

impl TryFrom<String> for FlowFilterPredicate {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let mut input = s.as_str();

        let predicate = parse_flow_filter_predicate
            .parse_next(&mut input)
            .map_err(|e| format!("Bad flow predicate! {e:?}"))?;

        Ok(predicate)
    }
}

fn parse_flow_filter_predicate(input: &mut &str) -> winnow::Result<FlowFilterPredicate> {
    let left = atomic_predicate.parse_next(input)?;

    let maybe_right = opt(seq!(
        _: space0,
        _: literal("&&"),
        _: space0,
        atomic_predicate
    ))
    .parse_next(input)?;

    if let Some((right,)) = maybe_right {
        Ok(FlowFilterPredicate::And(Box::new(left), Box::new(right)))
    } else {
        Ok(left)
    }
}

fn atomic_predicate(input: &mut &str) -> winnow::Result<FlowFilterPredicate> {
    alt((tls_data_packets_comp, tls_version_comp)).parse_next(input)
}

fn tls_data_packets_comp(input: &mut &str) -> winnow::Result<FlowFilterPredicate> {
    let (n,) = seq!(
        _: literal("tlsDataPackets"),
        _: space0,
        _: literal(">="),
        _: space0,
        digit1,
    )
    .parse_next(input)?;

    Ok(FlowFilterPredicate::MinTLSDataPackets(
        n.parse::<usize>().unwrap(),
    ))
}

fn tls_version_comp(input: &mut &str) -> winnow::Result<FlowFilterPredicate> {
    let (version,) = seq!(
        _: literal("tlsVersion"),
        _: space0,
        _: literal("=="),
        _: space0,
        alt((
            literal("TLSv12").value(TLSVersion::TLSv12),
            literal("TLSv13").value(TLSVersion::TLSv13),
        ))
    )
    .parse_next(input)?;

    Ok(FlowFilterPredicate::TLSVersionEq(version))
}

// Allow the --flows command line option to override whatever is in config
pub fn resolve(config: &mut PipelineConfig, args: &CommonPipelineArgs) {
    if let FlowSource::Empirical {
        path,
        flow_filter: _,
    } = &mut config.flow.source_a
    {
        let new_path = args
            .flows
            .as_ref()
            .cloned()
            .or(path.take())
            .expect("Need to specify --flows on command line or [flows] in config file");

        *path = Some(new_path);
    }
}

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use winnow::Parser as WinnowParser;
use winnow::ascii::{digit1, space0};
use winnow::combinator::{alt, opt, seq};
use winnow::token::literal;

use crate::base::{FlowFilterPredicate, TLSVersion};
use crate::feature::FeatureKind;
use crate::obfuscation::TLSMode;

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
    Obfuscation(ObfuscationCli),
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
    /// A quantizer specification that bins features based on the provided TrafficStats
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long, default_value_t = 0)]
    pub markov_order: u32,
    #[arg(long, default_value_t = 0.05)]
    pub epsilon: f64,
    #[arg(long, default_value_t = 0.05)]
    pub delta: f64,
    #[arg(long)]
    pub mask: Option<Vec<FeatureKind>>,
}

#[derive(Debug, Args)]
pub struct StatsDisplayArgs {
    #[arg(long)]
    pub input: PathBuf,
    #[arg(long)]
    pub feature: Option<FeatureKind>,
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
    pub ml: Option<MLConfig>,
}

#[derive(Debug, serde::Deserialize)]
pub struct FlowConfig {
    pub source_a: FlowSource,
    pub strip_tls_handshake: bool,
    pub obfuscator: Option<ObfuscatorSpec>,
}

#[derive(Debug, serde::Deserialize)]
pub struct MLConfig {
    pub source_b: FlowSource,
    pub train_proportion: u8,
    pub features_packet_horizon: usize,
    pub raw_features: bool,
}

#[derive(Debug, Parser)]
pub struct PipelineCli {
    #[command(subcommand)]
    pub command: PipelineCommand,
}

#[derive(Debug, Subcommand)]
pub enum PipelineCommand {
    Histograms(PipelineHistogramsArgs),
    Ml(PipelineMlArgs),
}

#[derive(Debug, Args)]
pub struct CommonPipelineArgs {
    #[arg(long)]
    pub config: PathBuf,
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
pub struct PipelineMlArgs {
    #[command(flatten)]
    pub common: CommonPipelineArgs,
    /// Output path for training data
    #[arg(long)]
    pub train_path: PathBuf,
    /// Output path for testing data
    #[arg(long)]
    pub test_path: PathBuf,
    #[arg(long)]
    pub histograms: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct GenerateArgs {
    #[arg(long)]
    pub traffic_profile: PathBuf,
    #[arg(long)]
    pub model: PathBuf,
    #[arg(long)]
    pub num_flows: usize,
    #[arg(long)]
    pub flow_length: usize,
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
    /// Model assumptions JSON (provides the quantizer / feature mask)
    #[arg(long)]
    pub model_assumptions: PathBuf,
    /// Max packets per flow (N)
    #[arg(long, short = 'N')]
    pub max_packets: usize,
    /// Maximum number of flow rows to write
    #[arg(long, short = 'M', default_value_t = usize::MAX)]
    pub num_flows: usize,
    /// Minimum packets a flow must have to be included (default = max_packets)
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
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Debug, serde::Deserialize, Clone)]
#[serde(try_from = "String")]
pub enum ObfuscatorSpec {
    Random { tls_mode: TLSMode },
    FromFile(std::path::PathBuf),
}

impl TryFrom<String> for ObfuscatorSpec {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if let Some(rest) = s.strip_prefix("random:") {
            let tls_mode = TLSMode::try_from(rest.to_string())?;
            Ok(Self::Random { tls_mode })
        } else if let Some(path) = s.strip_prefix("file:") {
            if path.is_empty() {
                return Err("file:<path> requires a non-empty path".into());
            }
            Ok(Self::FromFile(PathBuf::from(path)))
        } else {
            Err("expected one of: random:<outer|inner|tls-in-tls>, file:<path>".into())
        }
    }
}

impl TryFrom<String> for TLSMode {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_str() {
            "outer" => Ok(TLSMode::Outer),
            "inner" => Ok(TLSMode::Inner),
            "tls-in-tls" => Ok(TLSMode::TLSInTLS),
            _ => Err("expected one of: outer, inner, tls-in-tls".to_string()),
        }
    }
}

#[derive(Debug, Parser)]
pub struct ObfuscationCli {
    #[command(subcommand)]
    pub command: ObfuscationCommands,
}

#[derive(Debug, Subcommand)]
pub enum ObfuscationCommands {
    RandProto(RandProtoArgs),
}

#[derive(Debug, Args)]
pub struct RandProtoArgs {
    #[arg(short, long)]
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
    #[arg(short, long)]
    pub input: String,
    #[arg(long)]
    pub index: usize,
    #[arg(long)]
    pub min_count: Option<usize>,
    #[arg(long)]
    pub min_probability: Option<f64>,
    #[arg(long)]
    pub top_k: Option<usize>,
    #[arg(long)]
    pub model: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct HistogramsMergeArgs {
    #[arg(short, long)]
    pub input: PathBuf,
    #[arg(short, long)]
    pub output: PathBuf,
}

#[derive(Debug, Args)]
pub struct HistogramsDivergenceArgs {
    #[arg(long)]
    pub left: PathBuf,
    #[arg(long)]
    pub right: PathBuf,
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
    #[arg(long)]
    pub input: PathBuf,
}

#[derive(Debug, Args)]
pub struct DivergenceDeltaArgs {
    #[arg(long)]
    pub input: PathBuf,
}

#[derive(Debug, Args)]
pub struct DivergenceTermsArgs {
    #[arg(long)]
    pub input: PathBuf,
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

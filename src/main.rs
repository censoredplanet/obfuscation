use std::error::Error;
use std::hash::BuildHasher;
use std::path::Path;
use std::time::SystemTime;

use clap::Parser;
use enumflags2::BitFlags;
use foldhash::fast::RandomState;
use hashbrown::HashMap;
use itertools::interleave;
use rand::Rng;
use rand::SeedableRng;
use rayon::prelude::*;

use crate::base::*;
use crate::cli::*;
use crate::divergence::*;
use crate::feature::*;
use crate::generator::*;
use crate::histograms::*;
use crate::merge::*;
use crate::obfuscation::*;
use crate::quantization::*;
use crate::stats::*;

pub mod base;
pub mod cli;
pub mod divergence;
pub mod feature;
pub mod generator;
pub mod histograms;
pub mod merge;
pub mod obfuscation;
pub mod quantization;
pub mod stats;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ModelAssumptions {
    pub markov_order: u32,
    pub quantizer: FlowQuantizer,
}

pub fn write_json<'a, T>(object: T, path: &Path) -> Result<(), Box<dyn Error>>
where
    T: serde::Serialize + 'a,
{
    let json = serde_json::to_string_pretty(&object)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub struct ShuffleBuffer<I: Iterator> {
    source: I,
    buffer: Vec<I::Item>,
}

impl<I: Iterator> ShuffleBuffer<I> {
    pub fn new(mut source: I, size: usize) -> Self {
        let mut buffer = Vec::with_capacity(size);
        source
            .by_ref()
            .take(size)
            .for_each(|item| buffer.push(item));
        Self { source, buffer }
    }
}

impl<I: Iterator> Iterator for ShuffleBuffer<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.is_empty() {
            return None;
        }

        let mut rng = rand::rng();
        let idx = rng.random_range(0..self.buffer.len());

        if let Some(next_item) = self.source.next() {
            Some(std::mem::replace(&mut self.buffer[idx], next_item))
        } else {
            // Source is empty, so we just shrink the buffer.
            // swap_remove is O(1).
            Some(self.buffer.swap_remove(idx))
        }
    }
}

struct CsvEmitter {
    record: csv::ByteRecord,
    int_buffer: itoa::Buffer,
    float_buffer: zmij::Buffer,
}

impl CsvEmitter {
    fn new() -> Self {
        Self {
            record: csv::ByteRecord::new(),
            int_buffer: itoa::Buffer::new(),
            float_buffer: zmij::Buffer::new(),
        }
    }

    fn clear(&mut self) {
        self.record.clear();
    }

    fn push_numeric(&mut self, value: f64) {
        let rounded = value.round();
        if value.is_finite() && (value - rounded).abs() < 1e-9 {
            self.record
                .push_field(self.int_buffer.format(rounded as i64).as_bytes());
        } else {
            self.record
                .push_field(self.float_buffer.format(value).as_bytes());
        }
    }
}

impl FeatureEmitter<f64> for CsvEmitter {
    fn push_feature(&mut self, value: f64) {
        self.push_numeric(value);
    }

    fn push_label(&mut self, label: usize) {
        self.record
            .push_field(self.int_buffer.format(label).as_bytes());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeatureEncoding {
    Raw,
    Quantized,
}

fn feature_width_for_packets(
    quantizer: &FlowQuantizer,
    num_packets: usize,
    encoding: FeatureEncoding,
) -> usize {
    (0..num_packets)
        .map(|idx| {
            let packet_quantizer = quantizer.quantizer_at(idx);
            match encoding {
                FeatureEncoding::Raw => {
                    let timestamp_active =
                        !matches!(packet_quantizer.timestamp.quantization, Quantization::Mask);
                    let size_active =
                        !matches!(packet_quantizer.size.quantization, Quantization::Mask);
                    usize::from(timestamp_active) + usize::from(size_active)
                }
                FeatureEncoding::Quantized => {
                    let timestamp_active =
                        !matches!(packet_quantizer.timestamp.quantization, Quantization::Mask);
                    let size_active =
                        !matches!(packet_quantizer.size.quantization, Quantization::Mask);
                    usize::from(timestamp_active) + usize::from(size_active)
                }
            }
        })
        .sum()
}

fn emit_flow_features(
    flow: &Flow,
    num_packets: usize,
    quantizer: &FlowQuantizer,
    emitter: &mut dyn FeatureEmitter<f64>,
    encoding: FeatureEncoding,
) {
    match encoding {
        FeatureEncoding::Raw => flow.emit_features(num_packets, quantizer, emitter),
        FeatureEncoding::Quantized => flow.emit_quantized_features(num_packets, quantizer, emitter),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Label {
    Tls,
    Obfuscated,
}

fn assign_to_split(flow_id: &[u8], hasher: &RandomState, train_proportion: u8) -> (Label, bool) {
    let hash = hasher.hash_one(to_key(flow_id));

    let kept_label = if (hash & 1) == 0 {
        Label::Tls
    } else {
        Label::Obfuscated
    };
    let is_train = ((hash >> 1) % 100) < train_proportion as u64;

    (kept_label, is_train)
}

fn write_flows_as_feature_vectors<'a, I>(
    flows: I,
    num_packets: usize,
    quantizer: &FlowQuantizer,
    train_path: &Path,
    test_path: &Path,
    train_proportion: u8,
    encoding: FeatureEncoding,
) -> Result<(), Box<dyn Error>>
where
    I: IntoIterator<Item = (&'a Flow, Label)>,
{
    let mut train_set_writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(train_path)?;
    let mut test_set_writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(test_path)?;

    let mut emitter = CsvEmitter::new();
    let record_width = 1 + feature_width_for_packets(quantizer, num_packets, encoding);

    let hasher = RandomState::default();

    for (flow, label) in flows {
        let (kept_label, is_train) = assign_to_split(flow.id(), &hasher, train_proportion);

        //println!("{:#?} {:#?} {:#?} {:#?}", flow.id(), label, kept_label, is_train);
        if label != kept_label {
            continue;
        }

        let writer = if is_train {
            &mut train_set_writer
        } else {
            &mut test_set_writer
        };

        //emitter.record.push_field(flow.id());

        match label {
            Label::Tls => emitter.push_label(0),
            Label::Obfuscated => emitter.push_label(1),
        }

        emit_flow_features(flow, num_packets, quantizer, &mut emitter, encoding);
        while emitter.record.len() < record_width {
            emitter.push_feature(-1.0);
        }

        writer.write_byte_record(&emitter.record)?;

        emitter.clear();
    }

    Ok(())
}

fn write_flows_to_csv<'a, I>(
    flows: I,
    quantizer: &FlowQuantizer,
    flow_length: usize,
    path: Option<&Path>,
    encoding: FeatureEncoding,
) -> Result<(), Box<dyn Error>>
where
    I: IntoIterator<Item = &'a Flow>,
{
    let mut emitter = CsvEmitter::new();

    match path {
        Some(p) => {
            let mut writer = csv::WriterBuilder::new().has_headers(false).from_path(p)?;
            for flow in flows {
                emit_flow_features(flow, flow_length, quantizer, &mut emitter, encoding);
                writer.write_byte_record(&emitter.record)?;
                emitter.clear();
            }
        }
        None => {
            let mut writer = csv::WriterBuilder::new()
                .has_headers(false)
                .from_writer(std::io::stdout());
            for flow in flows {
                emit_flow_features(flow, flow_length, quantizer, &mut emitter, encoding);
                writer.write_byte_record(&emitter.record)?;
                emitter.clear();
            }
        }
    }

    Ok(())
}

fn run_dump_csv(args: &DumpCsvArgs) -> Result<(), Box<dyn Error>> {
    let model_assumptions =
        serde_json::from_slice::<ModelAssumptions>(&std::fs::read(&args.model_assumptions)?)?;
    let min_packets = args.min_packets.unwrap_or(args.max_packets);
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(&args.output)?;
    let mut emitter = CsvEmitter::new();
    let mut total: usize = 0;
    let strip = args.strip_tls_handshake;
    let max_packets = args.max_packets;
    let num_flows = args.num_flows;
    let flow_filter = &args.flow_filter;

    let encoding = if args.quantized {
        FeatureEncoding::Quantized
    } else {
        FeatureEncoding::Raw
    };

    let quantizer: FlowQuantizer = if args.skip_timing {
        match model_assumptions.quantizer.clone() {
            FlowQuantizer::Global(mut pq) => {
                pq.timestamp.quantization = Quantization::Mask;
                FlowQuantizer::Global(pq)
            }
            FlowQuantizer::PerPacket(pqs) => FlowQuantizer::PerPacket(
                pqs.into_iter()
                    .map(|mut pq| {
                        pq.timestamp.quantization = Quantization::Mask;
                        pq
                    })
                    .collect(),
            ),
        }
    } else {
        model_assumptions.quantizer.clone()
    };

    let feature_width = feature_width_for_packets(&quantizer, max_packets, encoding);
    let mut io_err: Option<std::io::Error> = None;

    for path in &args.flows {
        if total >= num_flows {
            break;
        }

        stream_flows(path, |mut flow| {
            if !flow_filter.matches(&flow) {
                return std::ops::ControlFlow::Continue(());
            }

            if strip {
                flow.strip_tls_handshake();
            }

            flow.rtt_normalize();

            if flow.packets.len() < min_packets {
                return std::ops::ControlFlow::Continue(());
            }

            emit_flow_features(&flow, max_packets, &quantizer, &mut emitter, encoding);
            while emitter.record.len() < feature_width {
                emitter.push_feature(-1.0);
            }

            if let Err(e) = writer.write_byte_record(&emitter.record) {
                io_err = Some(e.into());
                return std::ops::ControlFlow::Break(());
            }
            emitter.clear();
            total += 1;

            if total >= num_flows {
                std::ops::ControlFlow::Break(())
            } else {
                std::ops::ControlFlow::Continue(())
            }
        })?;

        if let Some(e) = io_err {
            return Err(e.into());
        }
    }

    Ok(())
}

pub fn read_and_filter_flows(source: &FlowSource) -> Result<Vec<Flow>, Box<dyn Error>> {
    match source {
        FlowSource::Empirical { path, flow_filter } => {
            Ok(Vec::<Flow>::from_file(&path.as_ref().unwrap())?
                .into_par_iter()
                .filter(|flow| flow_filter.matches(flow))
                .collect::<Vec<Flow>>())
        }
        FlowSource::Generated {
            traffic_profile: _,
            quantizer: _,
            num_flows: _,
            flow_length: _,
        } => todo!(),
        FlowSource::Clone { .. } => unreachable!(),
    }
}

pub fn materialize_sources(
    source_a: &FlowSource,
    source_b: Option<&FlowSource>,
) -> Result<(Vec<Flow>, Option<Vec<Flow>>), Box<dyn std::error::Error>> {
    if matches!(source_a, FlowSource::Clone { .. }) {
        return Err("source_a cannot be Clone".into());
    }

    let flows_a = read_and_filter_flows(source_a)?;
    let flows_b = match source_b {
        None => None,
        Some(FlowSource::Clone { .. }) => Some(flows_a.clone()),
        Some(source) => Some(read_and_filter_flows(source)?),
    };

    Ok((flows_a, flows_b))
}

fn preprocess(flows: &mut [Flow], strip: bool) -> () {
    flows.par_iter_mut().for_each(|flow| {
        if strip {
            flow.strip_tls_handshake();
        }
        flow.rtt_normalize();
    });
}

fn prepare_flows(
    config: &PipelineConfig,
) -> Result<(Vec<Flow>, Option<Vec<Flow>>), Box<dyn std::error::Error>> {
    let source_b = config
        .ml
        .as_ref()
        .map(|ml_config| ml_config.source_b.clone());
    let (mut flows_a, mut flows_b) = materialize_sources(&config.flow.source_a, source_b.as_ref())?;

    let obfuscator = config
        .flow
        .obfuscator
        .as_ref()
        .map(|cfg| match &cfg {
            ObfuscatorSpec::Random { tls_mode } => {
                let obfuscator = Obfuscator::random(tls_mode.clone());
                println!("{:#?}", obfuscator);
                Ok::<Obfuscator, Box<dyn std::error::Error>>(obfuscator)
            }
            ObfuscatorSpec::FromFile(path) => {
                let bytes = std::fs::read(path)?;
                Ok::<Obfuscator, Box<dyn std::error::Error>>(serde_json::from_slice(&bytes)?)
            }
        })
        .transpose()?;

    if let Some(obfuscator) = obfuscator {
        match flows_b.as_mut() {
            Some(b) => {
                *b = obfuscator.obfuscate_flows(b);
            }
            None => {
                flows_a = obfuscator.obfuscate_flows(&flows_a);
            }
        }
    }

    preprocess(&mut flows_a, config.flow.strip_tls_handshake);
    if let Some(b) = flows_b.as_mut() {
        preprocess(b, config.flow.strip_tls_handshake);
    }

    Ok((flows_a, flows_b))
}

fn build_model(
    flows: &[Flow],
    quantizer: &FlowQuantizer,
    markov_order: u32,
    alpha: f64,
) -> TrafficProfile {
    let quantized = quantizer.quantize_flows(&flows);

    quantized
        .par_iter()
        .map(|flow| as_histogram(&flow, &quantizer, markov_order, alpha))
        .reduce(
            || TrafficProfile::empty(markov_order),
            |accumulator, traffic_profile| accumulator.merge(traffic_profile),
        )
}

fn shuffle_and_write_feature_vectors(
    flows_a: &[Flow],
    flows_b: &[Flow],
    model: &ModelAssumptions,
    config: &MLConfig,
    train_path: &Path,
    test_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let labeled_tls = flows_a.iter().map(|f| (f, Label::Tls));
    let labeled_obfs = flows_b.iter().map(|f| (f, Label::Obfuscated));

    let shuffler = ShuffleBuffer::new(interleave(labeled_tls, labeled_obfs), 100000);

    write_flows_as_feature_vectors(
        shuffler,
        config.features_packet_horizon,
        &model.quantizer,
        &train_path,
        &test_path,
        config.train_proportion,
        if config.raw_features {
            FeatureEncoding::Raw
        } else {
            FeatureEncoding::Quantized
        },
    )
}

fn build_and_write_histograms(
    flows_a: &[Flow],
    flows_b: Option<&[Flow]>,
    config: &PipelineConfig,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let model_assumptions = serde_json::from_slice::<ModelAssumptions>(&std::fs::read(
        &config.model.model_assumptions,
    )?)?;
    let target_flows = flows_b.unwrap_or(flows_a);
    let histograms = build_model(
        target_flows,
        &model_assumptions.quantizer,
        model_assumptions.markov_order,
        config.model.pseudocount,
    );
    histograms.write(output)
}

pub fn run_histograms_pipeline(
    config: PipelineConfig,
    args: PipelineHistogramsArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now();
    let (flows_a, flows_b) = prepare_flows(&config)?;
    println!("Preprocessing finished at {}s", now.elapsed()?.as_secs());
    build_and_write_histograms(&flows_a, flows_b.as_deref(), &config, &args.output)?;
    println!("Done at {}s", now.elapsed()?.as_secs());
    Ok(())
}

pub fn run_ml_pipeline(
    config: PipelineConfig,
    args: PipelineMlArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now();

    let model_assumptions = serde_json::from_slice::<ModelAssumptions>(&std::fs::read(
        &config.model.model_assumptions,
    )?)?;
    let ml_config = config.ml.as_ref().expect("ml config required");

    let (flows_a, flows_b) = prepare_flows(&config)?;
    println!("Preprocessing finished at {}s", now.elapsed()?.as_secs());
    shuffle_and_write_feature_vectors(
        &flows_a,
        flows_b.as_ref().unwrap(),
        &model_assumptions,
        &ml_config,
        &args.train_path,
        &args.test_path,
    )?;
    println!("Writing features finished at {}s", now.elapsed()?.as_secs());

    if let Some(ref histograms_path) = args.histograms {
        build_and_write_histograms(&flows_a, flows_b.as_deref(), &config, histograms_path)?;
        println!("Histograms finished at {}s", now.elapsed()?.as_secs());
    }
    println!("Done at {}s", now.elapsed()?.as_secs());

    Ok(())
}

fn load_pipeline_config(
    common: &CommonPipelineArgs,
) -> Result<PipelineConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(&common.config)?;
    let mut config: PipelineConfig = toml::from_str(&content)?;
    resolve(&mut config, common);
    println!("{:#?}", config);
    Ok(config)
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Zeek2Flows(args) => {
            let now = SystemTime::now();
            let flows = read_flows(&args.flows, &args.packets)?;
            println!("Reading finished at {:#?}s", now.elapsed()?.as_secs());
            flows.write(&args.output)?;
        }
        Commands::Stats(stats_cli) => match stats_cli.command {
            StatsCommand::Compute(args) => {
                let now = SystemTime::now();

                let mut flows = read_and_filter_flows(&FlowSource::Empirical {
                    path: Some(args.flows),
                    flow_filter: args.flow_filter,
                })?;
                println!(
                    "Reading {} flows finished at {:#?}s",
                    flows.len(),
                    now.elapsed()?.as_secs()
                );

                preprocess(&mut flows, args.strip_tls_handshake);

                let traffic_stats = TrafficStats::from_flows(&flows);

                println!("Done computing stats at {:#?}s", now.elapsed()?.as_secs());

                traffic_stats.write(&args.output)?;
            }
            StatsCommand::Merge(args) => {
                let merged = merge_from_directory::<TrafficStats>(&args.input)?;
                merged.write(&args.output)?;
            }
            StatsCommand::Bin(args) => {
                let traffic_stats = TrafficStats::from_file(&args.input)?;

                let mut feature_mask = BitFlags::<FeatureKind>::all();
                feature_mask.remove(FeatureKind::Entropy);
                args.mask
                    .iter()
                    .flatten()
                    .for_each(|&f| feature_mask.remove(f));

                let model_assumptions = ModelAssumptions {
                    markov_order: args.markov_order,
                    quantizer: FlowQuantizer::PerPacket(bin(
                        traffic_stats,
                        feature_mask,
                        args.markov_order,
                        args.epsilon,
                        args.delta,
                    )),
                };

                write_json(model_assumptions, &args.output)?;
            }
            StatsCommand::Display(args) => {
                let traffic_stats = TrafficStats::from_file(&args.input)?;

                let mut view = traffic_stats.view();

                if let Some(feature) = args.feature {
                    view = view.feature(feature);
                }
                if let Some(index) = args.index {
                    view = view.index(index);
                }

                println!("{}", view);
            }
        },
        Commands::Pipeline(pipeline_cli) => match pipeline_cli.command {
            PipelineCommand::Histograms(args) => {
                run_histograms_pipeline(load_pipeline_config(&args.common)?, args)?
            }
            PipelineCommand::Ml(args) => {
                run_ml_pipeline(load_pipeline_config(&args.common)?, args)?
            }
        },
        Commands::Generate(args) => {
            let traffic_profile = TrafficProfile::from_file(&args.traffic_profile)?;
            let model_assumptions =
                serde_json::from_slice::<ModelAssumptions>(&std::fs::read(args.model)?)?;

            if traffic_profile.markov_order != model_assumptions.markov_order {
                return Err(format!(
                    "traffic profile markov_order ({}) does not match model assumptions markov_order ({})",
                    traffic_profile.markov_order,
                    model_assumptions.markov_order
                ).into());
            }

            let samplers = traffic_profile
                .profile
                .iter()
                .map(|histogram| {
                    histogram
                        .conditional_histogram()
                        .into_iter()
                        .map(|(prefix, conditional_histogram)| {
                            (prefix, WeightedSampler::from(&conditional_histogram))
                        })
                        .collect::<HashMap<_, _>>()
                })
                .collect::<Vec<_>>();

            let seed = args.seed.unwrap_or_else(|| rand::random::<u64>());
            let rng = rand::rngs::StdRng::seed_from_u64(seed);
            let flows = generate_flows(
                &samplers,
                &model_assumptions.quantizer,
                traffic_profile.markov_order,
                args.num_flows,
                args.flow_length,
                rng,
            )?;

            let encoding = if args.quantized {
                FeatureEncoding::Quantized
            } else {
                FeatureEncoding::Raw
            };
            write_flows_to_csv(
                &flows,
                &model_assumptions.quantizer,
                args.flow_length,
                args.output.as_deref(),
                encoding,
            )?;
        }
        Commands::DumpCsv(args) => {
            run_dump_csv(&args)?;
        }
        Commands::Obfuscation(obfuscation_cli) => match obfuscation_cli.command {
            ObfuscationCommands::RandProto(args) => {
                let obfuscator = Obfuscator::random(TLSMode::Inner);
                write_json(obfuscator, &args.output)?;
            }
        },
        Commands::Histograms(histograms_cli) => match histograms_cli.command {
            HistogramsCommands::Display(args) => {
                let histograms =
                    Vec::<Histogram<PacketProjection>>::from_file(Path::new(&args.input))?;
                let mut view = HistogramViewBuilder::new()
                    .min_count(args.min_count)
                    .min_probability(args.min_probability)
                    .top_k(args.top_k)
                    .from_histogram(&histograms[args.index]);

                if let Some(model) = args.model {
                    let model = serde_json::from_slice::<ModelAssumptions>(&std::fs::read(model)?)?;
                    let packet_quantizer = model.quantizer.quantizer_at(args.index);
                    view = view.with_quantizer(packet_quantizer);
                    println!("{}", view);
                } else {
                    println!("{}", view);
                }
            }
            HistogramsCommands::Divergence(args) => {
                let left = TrafficProfile::from_file(&args.left)?;
                let right = TrafficProfile::from_file(&args.right)?;

                let kl_divergence = left.kl_divergence(&right);

                kl_divergence.write(&args.output)?;
            }
            HistogramsCommands::Merge(args) => {
                let traffic_profile = merge_from_directory::<TrafficProfile>(&args.input)?;
                traffic_profile.write(&args.output)?;
            }
        },
        Commands::Divergence(divergence_cli) => match divergence_cli.command {
            DivergenceCommands::Cumulative(args) => {
                let divergence = KLDivergence::from_file(&args.input)?;
                println!("{:?}", divergence.cumulative_divergence());
            }
            DivergenceCommands::Delta(args) => {
                let divergence = KLDivergence::from_file(&args.input)?;
                println!("{:?}", divergence.per_index_divergence());
            }
            DivergenceCommands::Terms(args) => {
                let divergence = KLDivergence::from_file(&args.input)?;
                println!("{:?}", divergence.max_index());
                divergence.max_packet_at_idx(1);
            }
        },
    }

    Ok(())
}

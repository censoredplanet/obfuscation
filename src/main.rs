use std::error::Error;
use std::time::SystemTime;
use std::path::Path;
use std::hash::BuildHasher;

use clap::Parser;
use rayon::prelude::*;
use rand::Rng;
use hashbrown::HashMap;
use foldhash::fast::RandomState;
use itertools::interleave;
use enumflags2::BitFlags;

use crate::cli::*;
use crate::merge::*;
use crate::base::*;
use crate::stats::*;
use crate::feature::*;
use crate::generator::*;
use crate::obfuscation::*;
use crate::quantization::*;
use crate::histograms::*;
use crate::divergence::*;

pub mod merge;
pub mod cli;
pub mod base;
pub mod stats;
pub mod feature;
pub mod generator;
pub mod obfuscation;
pub mod quantization;
pub mod histograms;
pub mod divergence;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ModelAssumptions {
    pub markov_order: u32,
    pub quantizer: FlowQuantizer,
}

pub fn write_json<'a, T>(
    object: T,
    path: &Path,
) -> Result<(), Box<dyn Error>>
where
    T: serde::Serialize + 'a,
{
    let json = serde_json::to_string_pretty(&object)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub struct ShuffleBuffer<I: Iterator> {
    source: I,
    buffer: Vec<I::Item>
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
}

impl FeatureEmitter<f64> for CsvEmitter {
    fn push_feature(&mut self, value: f64) {
        self.record.push_field(self.float_buffer.format(value).as_bytes());
    }

    fn push_label(&mut self, label: usize) {
        self.record.push_field(self.int_buffer.format(label).as_bytes());
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Label {
    Tls,
    Obfuscated
}

fn assign_to_split(flow_id: &[u8], hasher: &RandomState, train_proportion: u8) -> (Label, bool) {
    let hash = hasher.hash_one(to_key(flow_id));

    let kept_label = if (hash & 1) == 0 { Label::Tls } else { Label::Obfuscated };
    let is_train = ((hash >> 1) % 100) < train_proportion as u64;

    (kept_label, is_train)
}

pub fn write_flows_as_feature_vectors<'a, I, F>(
    flows: I, 
    num_packets: usize, 
    train_path: &Path,
    test_path: &Path,
    train_proportion: u8) -> Result<(), Box<dyn Error>> 
where
    I: IntoIterator<Item = (&'a F, Label)>,
    F: EmitFeatures<Value = f64> + 'a
{
    let mut train_set_writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(train_path)?;
    let mut test_set_writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(test_path)?;
    
    let mut emitter = CsvEmitter::new();

    let hasher = RandomState::default();

    for (flow, label) in flows {
        let (kept_label, is_train) = assign_to_split(flow.id(), &hasher, train_proportion);

        //println!("{:#?} {:#?} {:#?} {:#?}", flow.id(), label, kept_label, is_train);
        if label != kept_label { continue; }

        let writer = if is_train { &mut train_set_writer } else { &mut test_set_writer };

        //emitter.record.push_field(flow.id());

        match label {
            Label::Tls => { emitter.push_label(0) },
            Label::Obfuscated => { emitter.push_label(1) }
        }

        flow.emit_features(num_packets, &mut emitter);
        while emitter.record.len() < 2 * num_packets {
            emitter.push_feature(-1.0);
        }

        writer.write_byte_record(&emitter.record)?;

        emitter.clear();
    }

    Ok(())
}

pub fn write_as_feature_vectors(flows: &[QuantizedFlow], quantization_scheme: &FlowQuantizer, num_packets: usize, path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = csv::WriterBuilder::new()
                        .has_headers(false)
                        .from_path(path)?;

    let num_features = quantization_scheme.min_features(num_packets);
    
    let mut feature_vector = Vec::with_capacity(num_features);
    let mut record = csv::ByteRecord::new();
    let mut buffer = itoa::Buffer::new();

    for flow in flows.iter() {
        flow.quantized.to_feature_vector(num_packets, &mut feature_vector);
        feature_vector.extend(std::iter::repeat(-1).take(num_features - feature_vector.len()));

        record.push_field(flow.conn_id);

        for feature in feature_vector.iter() {
            record.push_field(buffer.format(*feature).as_bytes());
        }

        writer.write_byte_record(&record)?;

        feature_vector.clear();
        record.clear();
    }
    
    Ok(())
}

pub fn read_and_filter_flows(source: &FlowSource) -> Result<Vec<Flow>, Box<dyn Error>> {
    match source {
        FlowSource::Empirical { path, flow_filter } => {
            Ok(Vec::<Flow>::from_file(path)?
                .into_par_iter()
                .filter(|flow| flow_filter.matches(flow))
                .collect::<Vec<Flow>>())
        },
        FlowSource::Generated { traffic_profile: _, quantizer: _, num_flows: _, flow_length: _ } => todo!(),
        FlowSource::Clone { .. } => unreachable!()
    }
}

pub fn materialize_sources(source_a: &FlowSource, source_b: Option<&FlowSource>) -> Result<(Vec<Flow>, Option<Vec<Flow>>), Box<dyn std::error::Error>> {
    if matches!(source_a, FlowSource::Clone { .. }) {
        return Err("source_a cannot be Clone".into());
    }

    let flows_a = read_and_filter_flows(source_a)?;
    let flows_b = match source_b {
        None => None,
        Some(FlowSource::Clone { .. }) => Some(flows_a.clone()),
        Some(source) => Some(read_and_filter_flows(source)?)
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

fn prepare_flows(config: &PipelineConfig) -> Result<(Vec<Flow>, Option<Vec<Flow>>), Box<dyn std::error::Error>> {
    let (mut flows_a, mut flows_b) = materialize_sources(&config.source_a, config.source_b.as_ref())?;

    let obfuscator = config.obfuscator
        .as_ref()
        .map(|cfg| {
            match &cfg {
                ObfuscatorSpec::Random { tls_mode } => {
                    let obfuscator = Obfuscator::random(tls_mode.clone());
                    println!("{:#?}", obfuscator);
                    Ok::<Obfuscator, Box<dyn std::error::Error>>(obfuscator)
                }
                ObfuscatorSpec::FromFile(path) => {
                    let bytes = std::fs::read(path)?;
                    Ok::<Obfuscator, Box<dyn std::error::Error>>(serde_json::from_slice(&bytes)?)
                }
            }
        })
        .transpose()?;

    if let Some(obfuscator) = obfuscator {
        match flows_b.as_mut() {
            Some(b) => { *b = obfuscator.obfuscate_flows(b); }
            None => { flows_a = obfuscator.obfuscate_flows(&flows_a); }
        }
    }

    preprocess(&mut flows_a, config.strip_tls_handshake);
    if let Some(b) = flows_b.as_mut() {
        preprocess(b, config.strip_tls_handshake);
    }

    Ok((flows_a, flows_b))
}

fn build_model(flows: &[Flow], quantizer: &FlowQuantizer, markov_order: u32, alpha: f64) -> TrafficProfile {
    let quantized = quantizer.quantize_flows(&flows);

    quantized.par_iter()
        .map(|flow| as_histogram(&flow, &quantizer, markov_order, alpha))
        .reduce(|| TrafficProfile::empty(markov_order),
            |accumulator, traffic_profile| accumulator.merge(traffic_profile))
}

fn run_ml_pipeline(
    flows_a: &[Flow], 
    flows_b: &[Flow], 
    config: &PipelineConfig, 
    train_path: &Path,
    test_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let labeled_tls = flows_a.iter().map(|f| (f, Label::Tls));
    let labeled_obfs = flows_b.iter().map(|f| (f, Label::Obfuscated));

    let shuffler = ShuffleBuffer::new(interleave(labeled_tls, labeled_obfs), 100000);

    write_flows_as_feature_vectors(
        shuffler, 
        config.features_packet_horizon, 
        &train_path,
        &test_path,
        config.train_proportion)
}

pub fn run_pipeline(config: PipelineConfig, args: PipelineArgs) -> Result<(), Box<dyn std::error::Error>> {
    //println!("{:#?}", args);

    let now = SystemTime::now();

    let (flows_a, flows_b) = prepare_flows(&config)?;
    println!("Preprocessing finished at {}s", now.elapsed()?.as_secs());

    if let Some(train_path) = args.train_set && 
        let Some(test_path) = args.test_set &&
        config.raw_features 
    {
        run_ml_pipeline(&flows_a, flows_b.as_ref().unwrap(), &config, &train_path, &test_path)?;
        println!("Writing features finished at {}s", now.elapsed()?.as_secs());
    }

    let target_flows = flows_b.as_ref().unwrap_or(&flows_a);
 
    let model_assumptions = serde_json::from_slice::<ModelAssumptions>(&std::fs::read(config.model.model_assumptions)?)?;
    let histograms = build_model(target_flows, &model_assumptions.quantizer, model_assumptions.markov_order, config.model.pseudocount);
    println!("Histograms finished at {}s", now.elapsed()?.as_secs());
    histograms.write(&args.histograms)?;

    println!("Done at {}s", now.elapsed()?.as_secs());

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Zeek2Flows(args) => {
            let now = SystemTime::now();
            let flows = read_flows(&args.flows, &args.packets)?;
            println!("Reading finished at {:#?}s", now.elapsed()?.as_secs());
            flows.write(&args.output)?;
        },
        Commands::Stats(stats_cli) => {
            match stats_cli.command {
                StatsCommand::Compute(args) => {
                    let now = SystemTime::now();

                    let mut flows = read_and_filter_flows(&FlowSource::Empirical {
                        path: args.flows, 
                        flow_filter: args.flow_filter
                    })?;
                    println!("Reading {} flows finished at {:#?}s", flows.len(), now.elapsed()?.as_secs());

                    preprocess(&mut flows, args.strip_tls_handshake);

                    let traffic_stats = TrafficStats::from_flows(&flows);

                    println!("Done computing stats at {:#?}s", now.elapsed()?.as_secs());

                    traffic_stats.write(&args.output)?;
                },
                StatsCommand::Merge(args) => {
                    let merged = merge_from_directory::<TrafficStats>(Path::new(&args.input))?;
                    merged.write(&args.output)?;
                },
                StatsCommand::Bin(args) => {
                    let traffic_stats = TrafficStats::from_file(Path::new(&args.input))?;

                    let mut feature_mask = BitFlags::<FeatureKind>::all();
                    feature_mask.remove(FeatureKind::Entropy);
                    args.mask.iter().flatten().for_each(|&f| feature_mask.remove(f));

                    let model_assumptions = ModelAssumptions {
                        markov_order: args.markov_order,
                        quantizer: FlowQuantizer::PerPacket(bin(traffic_stats, feature_mask, args.markov_order, args.epsilon, args.delta))
                    };

                    write_json(model_assumptions, &args.output)?;
                },
                StatsCommand::Display(args) => {
                    let traffic_stats = TrafficStats::from_file(Path::new(&args.input))?;
                    
                    let mut view = traffic_stats.view();
                    
                    if let Some(feature) = args.feature {
                        view = view.feature(feature);
                    }
                    if let Some(index) = args.index {
                        view = view.index(index);
                    }

                    println!("{}", view);
                }
            }
        },
        Commands::Pipeline(args) => {
            let content = std::fs::read_to_string(&args.config)?;
            let config: PipelineConfig = toml::from_str(&content)?;
            println!("{:#?}", config);
            run_pipeline(config, args)?
        }
        Commands::Generate(args) => {
            let traffic_profile = TrafficProfile::from_file(Path::new(&args.traffic_profile))?;
            let quantizer = serde_json::from_slice::<FlowQuantizer>(&std::fs::read(args.quantizer)?)?;

            let samplers = traffic_profile.profile.iter()
                .map(|histogram| {
                    histogram
                        .conditional_histogram()
                        .into_iter()
                        .map(|(prefix, conditional_histogram)| (prefix, WeightedSampler::from(&conditional_histogram)))
                        .collect::<HashMap<_, _>>()
                })
                .collect::<Vec<_>>();
            
            let generator = Generator::new(&samplers, quantizer, traffic_profile.markov_order, args.length, rand::rng());
            for packet in generator {
                println!("{:#?}", packet);
            }
        }
        Commands::Obfuscation(obfuscation_cli) => {
            match obfuscation_cli.command {
                ObfuscationCommands::RandProto(args) => {
                    let obfuscator = Obfuscator::random(TLSMode::Inner);
                    write_json(obfuscator, &args.output)?;
                }
            }
        },
        Commands::Histograms(histograms_cli) => {
            match histograms_cli.command {
                HistogramsCommands::Display(args) => {
                    let histograms = Vec::<Histogram<PacketProjection>>::from_file(Path::new(&args.input))?;
                    println!("{}", histograms[args.index]);
                }
                HistogramsCommands::Divergence(args) => {
                    let left = TrafficProfile::from_file(Path::new(&args.left))?;
                    let right = TrafficProfile::from_file(Path::new(&args.right))?;

                    let kl_divergence = left.kl_divergence(&right);
                    let reverse_kl_divergence = left.reverse_kl_divergence(&right);

                    println!("Cumulative Sum: {:#?}", kl_divergence.cumulative_divergence());
                    println!("Bayes Error (Lower Bound): {:#?}", kl_divergence.bayes_error_lower_bound());

                    println!("Chernoff-Stein: {:#?}", kl_divergence.chernoff_stein_lemma(1000));
                    println!("Sanov: {:#?}", reverse_kl_divergence.sanovs_theorem(1000));
                }
                HistogramsCommands::Merge(args) => {
                    let traffic_profile = merge_from_directory::<TrafficProfile>(&args.input)?;
                    traffic_profile.write(&args.output)?;
                }
            }
        },
    }

    Ok(())
}

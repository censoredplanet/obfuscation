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
        FlowSource::Generated { traffic_profile, quantizer, num_flows, flow_length } => todo!(),
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

// TODO: split into ML and regular pipelines
pub fn run_pipeline(config: PipelineConfig, args: PipelineArgs) -> Result<(), Box<dyn std::error::Error>> {
    //println!("{:#?}", args);

    let now = SystemTime::now();

    let (mut flows, mut flows_b) = materialize_sources(&config.source_a, config.source_b.as_ref())?;
    println!("Reading {} flows finished at {:#?}s", flows.len(), now.elapsed()?.as_secs());

    let obfuscator = config.obfuscator
        .map(|cfg| {
            match cfg.obfuscator {
                ObfuscatorSpec::Random => {
                    let obfuscator = Obfuscator::random(cfg.tls_mode);
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
            Some(flows_b) => { *flows_b = obfuscator.obfuscate_flows(flows_b); }
            None => { flows_a = obfuscator.obfuscate_flows(&flows_a); }
        }
    }

    let preprocess = |flows: &mut [Flow], strip: bool| {
        flows.par_iter_mut().for_each(|flow| {
            if strip {
                flow.strip_tls_handshake();
            }
            flow.rtt_normalize();
        });
    };

    preprocess(&mut flows_a, config.strip_tls_handshake);
    preprocess(&mut flows_b, config.strip_tls_handshake);
    
    println!("Obfuscation finished at {:#?}s", now.elapsed()?.as_secs());

    if let Some(train_path) = args.train_set && 
        let Some(test_path) = args.test_set &&
        config.raw_features 
    {
        let labeled_tls = flows_a.iter().map(|f| (f, Label::Tls));
        let labeled_obfs = flows_b.iter().map(|f| (f, Label::Obfuscated));

        let shuffler = ShuffleBuffer::new(interleave(labeled_tls, labeled_obfs), 100000);

        write_flows_as_feature_vectors(
            shuffler, 
            config.features_packet_horizon, 
            &train_path,
            &test_path,
            config.train_proportion)?;
        println!("Writing features finished at {:#?}s", now.elapsed()?.as_secs());
    }

    let quantizer = serde_json::from_slice::<FlowQuantizer>(&std::fs::read(config.model.quantizer)?)?;

    let quantized = quantizer.quantize_flows(&obfuscated);
    println!("Quantizing finished at {:#?}s", now.elapsed()?.as_secs());

    let h = quantized.par_iter()
                        .map(|flow| as_histogram(&flow, &quantizer, config.model.markov_order))
                        .reduce(|| TrafficProfile::empty(config.model.markov_order),
                            |mut accumulator, traffic_profile| accumulator.merge(traffic_profile));
    
    println!("Histograms finished at {:#?}s", now.elapsed()?.as_secs());

    h.write(&args.histograms)?;

    println!("Done at {:#?}s", now.elapsed()?.as_secs());

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

                    flows.par_iter_mut()
                        .for_each(|flow| {
                            if args.strip_tls_handshake {
                                flow.strip_tls_handshake();
                            }
                            flow.rtt_normalize();
                        });

                    let mut traffic_stats = TrafficStats::default();
                    for flow in flows.iter() {
                        traffic_stats.update(&flow);
                    }

                    println!("Done computing stats at {:#?}s", now.elapsed()?.as_secs());

                    traffic_stats.write(&args.output)?;
                },
                StatsCommand::Merge(args) => {
                    let merged = merge_from_directory::<TrafficStats>(Path::new(&args.input))?;
                    merged.write(&args.output)?;
                },
                StatsCommand::Bin(args) => {
                    let traffic_stats = TrafficStats::from_file(Path::new(&args.input))?;
                    let flow_quantizer = FlowQuantizer::PerPacket(
                        bin(traffic_stats, args.markov_order, args.epsilon, args.delta));
                    write_json(flow_quantizer, &args.output)?;

                }
            }
        },
        Commands::Pipeline(args) => {
            let content = std::fs::read_to_string("config.toml")?;
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
            
            let mut generator = Generator::new(&samplers, quantizer, traffic_profile.markov_order, args.length, rand::rng());
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
                HistogramsCommands::Merge(args) => {
                    let traffic_profile = merge_from_directory::<TrafficProfile>(&args.input)?;
                    traffic_profile.write(&args.output)?;
                }
            }
        },
        Commands::Divergence(args) => {
            let baseline = TrafficProfile::from_file(Path::new(&args.baseline))?;
            let other = TrafficProfile::from_file(Path::new(&args.other))?;

            let divergence = baseline.divergence(&other);
            println!("{:#?}", divergence);
        }
    }

    Ok(())
}

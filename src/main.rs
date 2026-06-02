use std::error::Error;
use std::path::Path;
use std::time::SystemTime;

use clap::Parser;
use enumflags2::BitFlags;
use hashbrown::HashMap;
use rand::SeedableRng;

use crate::base::*;
use crate::cli::*;
use crate::divergence::*;
use crate::feature::*;
use crate::generator::*;
use crate::histograms::*;
use crate::merge::*;
use crate::output::*;
use crate::pipeline::*;
use crate::quantization::*;
use crate::stats::*;

pub mod base;
pub mod cli;
pub mod divergence;
pub mod feature;
pub mod generator;
pub mod histograms;
pub mod merge;
pub mod output;
pub mod pipeline;
pub mod quantization;
pub mod stats;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ModelAssumptions {
    pub markov_order: u32,
    pub quantizer: FlowQuantizer,
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
                divergence.max_packet_at_idx(args.index);
            }
        },
    }

    Ok(())
}

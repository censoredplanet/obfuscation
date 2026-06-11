use std::error::Error;
use std::path::Path;
use std::time::SystemTime;

use rayon::prelude::*;

use crate::base::Flow;
use crate::cli::{CommonPipelineArgs, PipelineHistogramsArgs};
use crate::divergence::TrafficProfile;
use crate::merge::{Merge, PostcardIO};
use crate::quantization::{as_histogram, FlowQuantizer};
use crate::ModelAssumptions;

pub fn read_and_filter_flows(source: &crate::cli::FlowSource) -> Result<Vec<Flow>, Box<dyn Error>> {
    match source {
        crate::cli::FlowSource::Empirical { path, flow_filter } => {
            Ok(Vec::<Flow>::from_file(&path.as_ref().unwrap())?
                .into_par_iter()
                .filter(|flow| flow_filter.matches(flow))
                .collect::<Vec<Flow>>())
        }
    }
}

pub fn preprocess(flows: &mut [Flow], strip: bool) -> () {
    flows.par_iter_mut().for_each(|flow| {
        if strip {
            flow.strip_tls_handshake();
        }
        flow.rtt_normalize();
    });
}

pub fn prepare_flows(
    config: &crate::cli::PipelineConfig,
) -> Result<Vec<Flow>, Box<dyn std::error::Error>> {
    let mut flows = read_and_filter_flows(&config.flow.source_a)?;
    preprocess(&mut flows, config.flow.strip_tls_handshake);
    Ok(flows)
}

pub fn build_model(
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

pub fn build_and_write_histograms(
    flows: &[Flow],
    config: &crate::cli::PipelineConfig,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let model_assumptions = serde_json::from_slice::<ModelAssumptions>(&std::fs::read(
        &config.model.model_assumptions,
    )?)?;
    let histograms = build_model(
        flows,
        &model_assumptions.quantizer,
        model_assumptions.markov_order,
        config.model.pseudocount,
    );
    histograms.write(output)
}

pub fn run_histograms_pipeline(
    config: crate::cli::PipelineConfig,
    args: PipelineHistogramsArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now();
    let flows = prepare_flows(&config)?;
    println!("Preprocessing finished at {}s", now.elapsed()?.as_secs());
    build_and_write_histograms(&flows, &config, &args.output)?;
    println!("Done at {}s", now.elapsed()?.as_secs());
    Ok(())
}

pub fn load_pipeline_config(
    common: &CommonPipelineArgs,
) -> Result<crate::cli::PipelineConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(&common.config)?;
    let mut config: crate::cli::PipelineConfig = toml::from_str(&content)?;
    crate::cli::resolve(&mut config, common);
    println!("{:#?}", config);
    Ok(config)
}

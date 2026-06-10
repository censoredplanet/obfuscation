use std::error::Error;
use std::path::Path;

use rand::SeedableRng;
use rand::seq::SliceRandom;
use rand::Rng;

use crate::base::Flow;
use crate::feature::{EmitFeatures, FeatureEmitter};
use crate::feature::FeatureKind;
use crate::quantization::{BoundedFeature, FeatureQuantizer, FlowQuantizer, PacketQuantizer};
use crate::quantization::Quantization;

pub fn write_json<'a, T>(object: T, path: &Path) -> Result<(), Box<dyn Error>>
where
    T: serde::Serialize + 'a,
{
    let json = serde_json::to_string_pretty(&object)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub struct CsvEmitter {
    pub record: csv::ByteRecord,
    int_buffer: itoa::Buffer,
    float_buffer: zmij::Buffer,
}

impl CsvEmitter {
    pub fn new() -> Self {
        Self {
            record: csv::ByteRecord::new(),
            int_buffer: itoa::Buffer::new(),
            float_buffer: zmij::Buffer::new(),
        }
    }

    pub fn clear(&mut self) {
        self.record.clear();
    }

    pub fn push_numeric(&mut self, value: f64) {
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
pub enum FeatureEncoding {
    Raw,
    Quantized,
}

pub fn feature_width_for_packets(
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

pub fn emit_flow_features(
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

pub fn write_flows_to_csv<'a, I>(
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

fn default_unmasked_quantizer() -> FlowQuantizer {
    FlowQuantizer::Global(PacketQuantizer {
        timestamp: FeatureQuantizer {
            feature: BoundedFeature::new(FeatureKind::Timestamp),
            quantization: Quantization::Uniform { inv_width: 1.0 },
        },
        direction: FeatureQuantizer {
            feature: BoundedFeature::new(FeatureKind::Direction),
            quantization: Quantization::Identity,
        },
        size: FeatureQuantizer {
            feature: BoundedFeature::new(FeatureKind::Size),
            quantization: Quantization::Identity,
        },
    })
}

fn estimate_rtt(flow: &Flow) -> f64 {
    let client_to_observer = (flow.base.ack_ts - flow.base.synack_ts) / 2.0;
    (flow.base.synack_ts - flow.base.syn_ts) + (2.0 * client_to_observer)
}

fn convert_timestamps_to_iats(flow: &mut Flow, scale: f64) {
    let mut prev_c2s_ts = None;
    let mut prev_s2c_ts = None;

    for packet in flow.packets.iter_mut() {
        let prev_ts = if packet.direction > 0.5 {
            &mut prev_c2s_ts
        } else {
            &mut prev_s2c_ts
        };

        let iat = match *prev_ts {
            None => 0.0,
            Some(ts) => packet.timestamp - ts,
        };

        *prev_ts = Some(packet.timestamp);
        packet.timestamp = iat / scale;
    }
}

pub fn run_dump_csv(args: &crate::cli::DumpCsvArgs) -> Result<(), Box<dyn Error>> {
    if args.quantized && args.model_assumptions.is_none() {
        return Err("--model-assumptions is required when using --quantized".into());
    }
    if args.sample_rate <= 0.0 || args.sample_rate > 1.0 {
        return Err("--sample-rate must be in (0.0, 1.0]".into());
    }

    let base_quantizer: FlowQuantizer = match &args.model_assumptions {
        Some(path) => {
            let ma = serde_json::from_slice::<crate::ModelAssumptions>(&std::fs::read(path)?)?;
            ma.quantizer
        }
        None => default_unmasked_quantizer(),
    };
    let min_packets = args.min_packets.unwrap_or(0);
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(&args.output)?;
    let mut emitter = CsvEmitter::new();
    let mut total: usize = 0;
    let strip = args.strip_tls_handshake;
    let max_packets = args.max_packets;
    let num_flows = args.num_flows;
    let flow_filter = &args.flow_filter;
    let include_rtt = args.include_rtt;
    let sample_rate = args.sample_rate;

    let encoding = if args.quantized {
        FeatureEncoding::Quantized
    } else {
        FeatureEncoding::Raw
    };

    let quantizer: FlowQuantizer = if args.skip_timing {
        match base_quantizer {
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
        base_quantizer
    };

    let feature_width = feature_width_for_packets(&quantizer, max_packets, encoding);
    let mut io_err: Option<std::io::Error> = None;

    let seed = args.seed.unwrap_or_else(|| rand::random::<u64>());
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut current_rate = sample_rate;

    loop {
        let mut paths: Vec<&std::path::PathBuf> = args.flows.iter().collect();
        paths.shuffle(&mut rng);

        for path in &paths {
            if total >= num_flows {
                break;
            }

            crate::base::stream_flows(path, |mut flow| {
                if !flow_filter.matches(&flow) {
                    return std::ops::ControlFlow::Continue(());
                }

                // Bernoulli sampling: skip this flow with probability (1 - current_rate)
                if current_rate < 1.0 && rng.random::<f64>() >= current_rate {
                    return std::ops::ControlFlow::Continue(());
                }

                if strip {
                    flow.strip_tls_handshake();
                }

                let rtt = estimate_rtt(&flow);
                if include_rtt {
                    convert_timestamps_to_iats(&mut flow, 1.0);
                } else {
                    flow.rtt_normalize();
                }

                if flow.packets.len() < min_packets {
                    return std::ops::ControlFlow::Continue(());
                }

                if include_rtt {
                    emitter.push_numeric(rtt);
                }
                emit_flow_features(&flow, max_packets, &quantizer, &mut emitter, encoding);
                while emitter.record.len() < feature_width + include_rtt as usize {
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

            if let Some(e) = io_err.take() {
                return Err(e.into());
            }
        }

        if total >= num_flows || current_rate >= 1.0 {
            break;
        }

        // sample_rate was too low; retry with a higher rate over a fresh shuffle
        let next_rate = (current_rate * 2.0).min(1.0);
        eprintln!(
            "warning: collected {}/{} flows at sample_rate={:.4}; retrying at {:.4}",
            total, num_flows, current_rate, next_rate
        );
        current_rate = next_rate;
    }

    if total < num_flows && num_flows != usize::MAX {
        eprintln!(
            "warning: binary files only yielded {total} matching flows (target was {num_flows})"
        );
    }

    Ok(())
}

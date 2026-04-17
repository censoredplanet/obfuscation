use std::fmt;
use std::hash::Hash;

use rand::distr::Distribution;
use rand::distr::weighted::WeightedIndex;

use rayon::prelude::*;
use rv::prelude::*;

use crate::base::{Packet, Flow};
use crate::feature::{FeatureKind, FeatureValueType};
use crate::histograms::{Sequence, Histogram};
use crate::TrafficProfile;

#[derive(Debug, serde::Serialize, serde::Deserialize, Copy, Clone, PartialEq, Eq, Hash)]
pub enum FeatureValue {
    Masked,
    Bin(u32),
}

impl FeatureValue {
    pub fn to_i64(&self) -> i64 {
        match *self {
            FeatureValue::Masked => -1,
            FeatureValue::Bin(bin) => bin as i64
        }
    }
}

impl fmt::Display for FeatureValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match *self {
            FeatureValue::Masked => "MASK",
            FeatureValue::Bin(bin) => &bin.to_string()
        };

        write!(f, "{}", value)
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PacketProjection {
    pub timestamp: FeatureValue,
    pub direction: FeatureValue,
    pub size: FeatureValue,
    pub entropy: FeatureValue
}

impl PacketProjection {
    pub fn to_array(&self) -> [i64; 4] {
        [
            self.timestamp.to_i64(),
            self.direction.to_i64(),
            self.size.to_i64(),
            self.entropy.to_i64()
        ]
    }
}

pub struct PacketProjectionDisplay<'a> {
    pub projection: &'a PacketProjection,
    pub quantizer: Option<&'a PacketQuantizer>,
}

impl fmt::Display for PacketProjectionDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let feature_as_interval_str = |bin: &FeatureValue, quantizer: &FeatureQuantizer| {
            match bin {
                FeatureValue::Masked => "".to_string(),
                FeatureValue::Bin(idx) => quantizer.bin_to_interval(*idx)
            }
        };

        if let Some(q) = self.quantizer {
            write!(f, "[t={}:{} d={}:{} s={}:{} e={}:{}]",
                self.projection.timestamp, feature_as_interval_str(&self.projection.timestamp, &q.timestamp),
                self.projection.direction, feature_as_interval_str(&self.projection.direction, &q.direction),
                self.projection.size, feature_as_interval_str(&self.projection.size, &q.size),
                self.projection.entropy, feature_as_interval_str(&self.projection.entropy, &q.entropy),
            )
        }
        else {
            write!(f, "[t={} d={} s={} e={}]", self.projection.timestamp, self.projection.direction, self.projection.size, self.projection.entropy)
        }
    }
}


#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct QuantizedPacketSequence {
    pub packets: Box<[PacketProjection]>
}

impl QuantizedPacketSequence {
    pub fn to_feature_vector(&self, num_packets: usize, feature_vector: &mut Vec<i64>) {
        for packet in self.packets.iter().take(num_packets) {
            feature_vector.extend(packet.to_array()
                                        .into_iter()
                                        .filter(|&v| v >= 0));
        }
    }
}

pub fn as_histogram(flow: &QuantizedFlow, quantizer: &FlowQuantizer, order: u32, pseudocount: f64) -> TrafficProfile {
    let num_packets = flow.quantized.packets.len();
    let mut histograms = Vec::with_capacity(num_packets);

    for i in 0..flow.quantized.packets.len() {
        let start = i.saturating_sub(order as usize);

        let alphabet_size = quantizer.quantizer_at(i).num_outcomes();
        let sequence_len = std::cmp::min(order as usize, i) + 1;
        let mut histogram = Histogram::new(alphabet_size, sequence_len, pseudocount);

        let seq = match quantizer {
            FlowQuantizer::Global(_) => flow.quantized.packets[start..=i].to_vec(),
            FlowQuantizer::PerPacket(_) => {
                (start..=i)
                    .map(|j| quantizer.quantizer_at(i).quantize_packet(&flow.raw[j]))
                    .collect::<Vec<_>>()
            }
        };

        histogram.increment(Sequence::from(seq));
        histograms.push(histogram);
    }

    TrafficProfile {
        profile: histograms,
        markov_order: order
    }
}

// for features with massive or infinite domains, instead of discretizing the entire
// domain, we can instead truncate the domain to the minimum/maximum observed values, 
// and then assign any out-of-bounds values to the first/last bins
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BoundedFeature {
    feature: FeatureKind,
    effective_min: f64,
    effective_max: f64
}

impl BoundedFeature {
    pub fn new(feature: FeatureKind) -> Self { BoundedFeature::new_with_bounds(feature, None, None) }
    pub fn new_with_bounds(feature: FeatureKind, maybe_effective_min: Option<f64>, maybe_effective_max: Option<f64>) -> Self {
        let domain = feature.domain();
        let effective_min = maybe_effective_min.unwrap_or(domain.min);
        let effective_max_inclusive = maybe_effective_max.unwrap_or(domain.max);

        assert!(domain.min <= effective_min && 
                effective_min <= effective_max_inclusive && 
                effective_max_inclusive <= domain.max);

        // Convert to half-open representation
        let effective_max = match feature.value_type() {
            FeatureValueType::Discrete => effective_max_inclusive + 1.0,
            FeatureValueType::Continuous => effective_max_inclusive,
        };

        BoundedFeature {
            feature: feature,
            effective_min: effective_min,
            effective_max: effective_max
        }
    }

    pub fn min(&self) -> f64 { self.feature.domain().min }
    pub fn max(&self) -> f64 { self.feature.domain().max }
    pub fn effective_min(&self) -> f64 { self.effective_min }
    pub fn effective_max(&self) -> f64 { self.effective_max }
    // rename? this is # outcomes and domain width for discrete rvs, but only domain
    // width for continuous ones
    pub fn domain_size(&self) -> f64 { self.effective_max() - self.effective_min() }

    pub fn feature(&self) -> &FeatureKind { &self.feature }
    pub fn value_type(&self) -> FeatureValueType { self.feature.value_type() }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Bin {
    values: Vec<usize>,
    counts: Vec<usize>
}

impl Bin {
    pub fn sample<R: rand::Rng>(&self, rng: &mut R) -> f64 {
        let weighted_index = WeightedIndex::new(&self.counts).unwrap();
        self.values[weighted_index.sample(rng)] as f64
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum Quantization {
    Mask,
    Identity,
    Uniform { inv_width: f64 },
    LogUniform { inv_log_width: f64 },
    Empirical {
        lookup: Vec<u32>,
        bins: Vec<Bin>,
    }
}

fn log_transform(value: f64) -> f64 {
    value.ln_1p()
}

fn log_inverse(value: f64) -> f64 {
    value.exp_m1()
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FeatureQuantizer {
    pub feature: BoundedFeature,
    pub quantization: Quantization,
}

impl FeatureQuantizer {
    pub fn mask(feature: BoundedFeature) -> Self {
        Self {
            feature: feature,
            quantization: Quantization::Mask
        }
    }

    pub fn identity(feature: BoundedFeature) -> Self {
        assert!(matches!(feature.value_type(), FeatureValueType::Discrete), 
                "Identity quantization only valid for discrete features.");

        Self {
            feature: feature,
            quantization: Quantization::Identity
        }
    }

    pub fn uniform_bounded(feature: BoundedFeature, bins: u32) -> Self {
        assert!(bins > 0, "Bins must be > 0");

        let width = feature.effective_max() - feature.effective_min();
        let inv_width = if width > 0.0 {
            bins as f64 / width
        } else {
            0.0
        };

        Self {
            feature: feature,
            quantization: Quantization::Uniform { inv_width: inv_width }
        }
    }

    pub fn log_uniform_bounded(feature: BoundedFeature, bins: u32) -> Self {
        assert!(bins > 0, "Bins must be > 0");
        assert!(feature.effective_min() >= 0.0, "Log quantization requires non-negative values");

        let width = log_transform(feature.effective_max()) - log_transform(feature.effective_min());
        let inv_log_width = if width > 0.0 {
            bins as f64 / width
        } else {
            0.0
        };

        Self {
            feature: feature,
            quantization: Quantization::LogUniform { inv_log_width: inv_log_width }
        }
    }

    // MaxDiff histograms are built such that bins - 1 boundaries are placed between values
    // with the largest absolute differences between them. This is designed to prevent values
    // with vastly different frequencies from being binned together.
    pub fn maxdiff(feature: BoundedFeature, frequencies: &[usize], bins: u32) -> Self {
        let mut diffs: Vec<(usize, isize)> = frequencies.windows(2)
            .enumerate()
            .map(|(i, w)| (i + 1, (w[1] as isize - w[0] as isize).abs()))
            .collect();

        diffs.sort_by(|(_, a), (_, b)| b.cmp(a));

        let mut boundaries: Vec<usize> = diffs.iter()
            .take((bins - 1) as usize)
            .map(|(i, _)| *i)
            .collect();
        boundaries.sort();

        let mut lookup = vec![0u32; feature.domain_size() as usize];
        let mut bin_vec: Vec<Bin> = Vec::with_capacity(bins as usize);

        let segment_starts = std::iter::once(0)
            .chain(boundaries.iter().copied())
            .collect::<Vec<_>>();
        let segment_ends = boundaries.iter().copied()
            .chain(std::iter::once(frequencies.len()))
            .collect::<Vec<_>>();

        for (bin_idx, (&start, &end)) in segment_starts.iter().zip(segment_ends.iter()).enumerate() {
            let mut values = Vec::new();
            let mut counts = Vec::new();

            for i in start..end {
                if frequencies[i] > 0 {
                    values.push(i);
                    counts.push(frequencies[i]);
                }
                lookup[i] = bin_idx as u32;
            }

            bin_vec.push(Bin { values, counts });
        }

        Self {
            feature,
            quantization: Quantization::Empirical { lookup, bins: bin_vec }
        }
    }

    pub fn num_bins(&self) -> usize {
        match &self.quantization {
            Quantization::Mask => 1,
            Quantization::Identity => (self.feature.effective_max() - self.feature.effective_min()) as usize,
            Quantization::Uniform { inv_width } => ((self.feature.domain_size() * inv_width).round() as usize).max(1),
            Quantization::LogUniform { inv_log_width } => {
                let log_domain = log_transform(self.feature.effective_max()) - log_transform(self.feature.effective_min());
                ((log_domain * inv_log_width).round() as usize).max(1)
            },
            Quantization::Empirical { lookup: _, bins } => bins.len()
        }
    }

    pub fn quantize_feature(&self, value: f64) -> FeatureValue {
        assert!(self.feature.min() <= value && value <= self.feature.max(), "Value {} out of range [{}, {}].", value, self.feature.min(), self.feature.max());

        match &self.quantization {
            Quantization::Mask => FeatureValue::Masked,
            Quantization::Identity => FeatureValue::Bin(value as u32),
            Quantization::Uniform { inv_width } => {
                let clamped = value
                    .max(self.feature.effective_min())
                    .min(self.feature.effective_max());
                let idx = ((clamped - self.feature.effective_min()) * inv_width).floor() as i64;
                FeatureValue::Bin(idx.clamp(0, self.num_bins() as i64 - 1) as u32)
            },
            Quantization::LogUniform { inv_log_width } => {
                let clamped = value
                    .max(self.feature.effective_min())
                    .min(self.feature.effective_max());
                let log_min = log_transform(self.feature.effective_min());
                let idx = ((log_transform(clamped) - log_min) * inv_log_width).floor() as i64;
                FeatureValue::Bin(idx.clamp(0, self.num_bins() as i64 - 1) as u32)
            },
            Quantization::Empirical { lookup, bins: _ } => FeatureValue::Bin(lookup[value as usize])
        }
    }

    pub fn dequantize<R: rand::Rng>(&self, feature: &FeatureValue, rng: &mut R) -> f64 {
        let mut sample_interval = |lo: f64, hi: f64| -> f64 {
            match self.feature.value_type() {
                FeatureValueType::Continuous => {
                    if lo < hi { Uniform::new(lo, hi).unwrap().draw(rng) } else { lo }
                }
                FeatureValueType::Discrete => {
                    let ilo = lo.ceil() as i64;
                    let ihi = hi.floor() as i64;
                    rng.random_range(ilo..=ihi) as f64
                }
            }
        };

        let bin = feature.to_i64();

        match &self.quantization {
            Quantization::Mask => sample_interval(self.feature.effective_min(), self.feature.effective_max()),
            Quantization::Identity => bin as f64,
            Quantization::Uniform { inv_width } => {
                let bin_width = 1.0 / inv_width;
                let lo = self.feature.effective_min() + bin as f64 * bin_width;
                let hi = (lo + bin_width).min(self.feature.effective_max());

                sample_interval(lo, hi)
            },
            Quantization::LogUniform { inv_log_width } => {
                let log_bin_width = 1.0 / inv_log_width;
                let log_min = log_transform(self.feature.effective_min());
                let log_max = log_transform(self.feature.effective_max());
                let lo = log_min + bin as f64 * log_bin_width;
                let hi = (lo + log_bin_width).min(log_max);
                let sample = if lo < hi { Uniform::new(lo, hi).unwrap().draw(rng) } else { lo };

                log_inverse(sample)
                    .max(self.feature.effective_min())
                    .min(self.feature.effective_max())
            },
            Quantization::Empirical { lookup: _, bins } => bins[bin as usize].sample(rng)
        }
    }

    fn bin_to_interval(&self, bin_idx: u32) -> String {
        match &self.quantization {
            Quantization::Mask => format!("[{}, {})", self.feature.effective_min(), self.feature.effective_max()),
            Quantization::Identity => {
                let v = bin_idx as f64 + self.feature.effective_min();
                format!("[{}, {}]", v, v)
            }
            Quantization::Uniform { inv_width } => {
                let bin_width = 1.0 / inv_width;
                let lo = self.feature.effective_min() + bin_idx as f64 * bin_width;
                let hi = (lo + bin_width).min(self.feature.effective_max());
                format!("[{}, {})", lo, hi)
            }
            Quantization::LogUniform { inv_log_width } => {
                let log_bin_width = 1.0 / inv_log_width;
                let log_min = log_transform(self.feature.effective_min());
                let lo = log_inverse(log_min + bin_idx as f64 * log_bin_width);
                let hi = log_inverse(log_min + (bin_idx + 1) as f64 * log_bin_width)
                    .min(self.feature.effective_max());
                format!("[{}, {})", lo, hi)
            }
            Quantization::Empirical { lookup: _, bins } => {
                let bin = &bins[bin_idx as usize];
                let lo = bin.values.first().copied().unwrap_or(0);
                let hi = bin.values.last().copied().unwrap_or(0);
                format!("[{}, {}]", lo, hi)
            }
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PacketQuantizer {
    pub timestamp: FeatureQuantizer,
    pub direction: FeatureQuantizer,
    pub size: FeatureQuantizer,
    pub entropy: FeatureQuantizer
}

impl PacketQuantizer {
    pub fn set_feature_quantizer(&mut self, quantizer: FeatureQuantizer) {
        match quantizer.feature.feature {
            FeatureKind::Timestamp => { self.timestamp = quantizer; },
            FeatureKind::Direction => { self.direction = quantizer; },
            FeatureKind::Size =>      { self.size = quantizer; },
            FeatureKind::Entropy =>   { self.entropy = quantizer; }
        }
    }

    pub fn num_active_features(&self) -> usize {
        (!matches!(self.timestamp.quantization, Quantization::Mask)) as usize +
        (!matches!(self.direction.quantization, Quantization::Mask)) as usize + 
        (!matches!(self.size.quantization, Quantization::Mask)) as usize + 
        (!matches!(self.entropy.quantization, Quantization::Mask)) as usize
    }

    pub fn num_outcomes(&self) -> usize {
        self.timestamp.num_bins() *
        self.direction.num_bins() *
        self.size.num_bins() *
        self.entropy.num_bins()
    }

    pub fn quantize_packet(&self, packet: &Packet) -> PacketProjection {
        PacketProjection {
            timestamp: self.timestamp.quantize_feature(packet.timestamp),
            direction: self.direction.quantize_feature(packet.direction),
            size: self.size.quantize_feature(packet.size),
            entropy: self.entropy.quantize_feature(packet.entropy),
        }
    }

    pub fn dequantize<R: rand::Rng>(&self, packet: &PacketProjection, rng: &mut R) -> Packet {
        Packet {
            timestamp: self.timestamp.dequantize(&packet.timestamp, rng),
            direction: self.direction.dequantize(&packet.direction, rng),
            size: self.size.dequantize(&packet.size, rng),
            entropy: self.entropy.dequantize(&packet.entropy, rng),
        }
    }
}

impl Default for PacketQuantizer {
    fn default() -> Self {
        PacketQuantizer {
            timestamp: FeatureQuantizer {
                feature: BoundedFeature::new_with_bounds(FeatureKind::Timestamp, None, Some(f64::MAX)),
                quantization: Quantization::Mask,
            },
            direction: FeatureQuantizer {
                feature: BoundedFeature::new(FeatureKind::Direction),
                quantization: Quantization::Mask,
            },
            size: FeatureQuantizer {
                feature: BoundedFeature::new(FeatureKind::Size),
                quantization: Quantization::Mask,
            },
            entropy: FeatureQuantizer {
                feature: BoundedFeature::new(FeatureKind::Entropy),
                quantization: Quantization::Mask,
            }
        }
    }
}

pub struct QuantizedFlow<'a> {
    pub conn_id: &'a [u8],
    pub raw: &'a [Packet],
    pub quantized: QuantizedPacketSequence
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum FlowQuantizer {
    Global(PacketQuantizer),
    PerPacket(Vec<PacketQuantizer>)
}

impl FlowQuantizer {
    pub fn quantizer_at(&self, idx: usize) -> &PacketQuantizer {
        match &self {
            FlowQuantizer::Global(quantizer) => &quantizer,
            FlowQuantizer::PerPacket(quantizers) => {
                assert!(idx < quantizers.len(), 
                    "Index {} greater than per-packet quantizers length {}", idx, quantizers.len());
                &quantizers[idx]
            }
        }
    }

    pub fn min_features(&self, num_packets: usize) -> usize {
        match &self {
            FlowQuantizer::Global(quantizer) => num_packets * quantizer.num_active_features(),
            FlowQuantizer::PerPacket(quantizers) => {
                assert!(num_packets < quantizers.len());
                quantizers.iter()
                            .take(num_packets)
                            .map(|quantizer| quantizer.num_active_features())
                            .sum()
            }
        }
    }

    fn quantize_packets(&self, packets: &[Packet]) -> QuantizedPacketSequence {
        let limit = match self {
            FlowQuantizer::Global(_) => packets.len(),
            FlowQuantizer::PerPacket(quantizers) => quantizers.len(),
        };

        QuantizedPacketSequence {
            packets: packets.iter()
                .take(limit)
                .enumerate()
                .map(|(idx, packet)| self.quantizer_at(idx).quantize_packet(packet))
                .collect()
        }
    }

    pub fn quantize_flows<'a>(&self, flows: &'a [Flow]) -> Vec<QuantizedFlow<'a>> {
        flows.par_iter().map(|flow| QuantizedFlow {
            conn_id: &flow.base.conn_id,
            raw: &flow.packets,
            quantized: self.quantize_packets(&flow.packets)
        }).collect()
    }
}

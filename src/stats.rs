use std::fmt;

use rayon::prelude::*;
use hashbrown::HashMap;
use tdigest::TDigest;
use enumflags2::BitFlags;

use crate::merge::{Merge, PostcardIO};
use crate::base::Flow;
use crate::feature::{FeatureKind};
use crate::quantization::{BoundedFeature, FeatureQuantizer, PacketQuantizer};

const TDIGEST_BUFFER_SIZE: usize = 4096;

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct FeatureStats {
    pub count: usize,
    pub mean: f64,
    pub m2: f64,
    pub min: f64,
    pub max: f64,
    pub tdigest: TDigest,
    // This is only needed for size, putting here for now
    // to avoid code refactoring.
    pub frequencies: Vec<usize>,
    #[serde(skip)]
    buffer: Vec<f64>,
}

impl FeatureStats {
    pub fn update(&mut self, value: f64) {
        self.count += 1;

        if let Some(count) = self.frequencies.get_mut(value.round() as usize) {
            *count += 1;
        }

        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;

        self.min = self.min.min(value);
        self.max = self.max.max(value);

        self.buffer.push(value);
    }

    pub fn flush_buffer(&mut self) {
        if !self.buffer.is_empty() {
            self.tdigest = self.tdigest.merge_unsorted(std::mem::take(&mut self.buffer));
        }
    }

    pub fn variance(&self) -> f64 {
        if self.count > 1 {
            self.m2 / (self.count - 1) as f64
        } else {
            0.0
        }
    }

    pub fn stddev(&self) -> f64 {
        self.variance().sqrt()
    }

    // Technically, any operations that read t-digest should flush the buffer to ensure
    // the t-digest is the most up-to-date. However, these operations are never done during
    // merging. A better design would maybe be to enforce that FeatureStats are finalized before
    // attempting to read them.
    pub fn iqr(&self) -> f64 {
        self.tdigest.estimate_quantile(0.75) - self.tdigest.estimate_quantile(0.25)
    }

    pub fn iqr2(&self) -> f64 {
        let quantile = |q: f64| -> usize {
            assert!(q <= 1.0, "quantile must be less than 1");
            let threshold = (self.count as f64 * q) as usize;
            let mut cumsum = 0;
            for (i, frequency) in self.frequencies.iter().enumerate() {
                cumsum += frequency;
                if cumsum >= threshold {
                    return i + 1;
                }
            }
            self.frequencies.len()
        };
        
        let q1 = quantile(0.25);
        let q3 = quantile(0.75);

        (q3 - q1) as f64
    }
}

impl Default for FeatureStats {
    fn default() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
            tdigest: TDigest::new_with_size(100),
            frequencies: vec![0; FeatureKind::Size.domain().max as usize],
            buffer: Vec::with_capacity(TDIGEST_BUFFER_SIZE)
        }
    }
}

impl fmt::Display for FeatureStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Count: {}", self.count)?;
        writeln!(f, "Mean: {}", self.mean)?;
        writeln!(f, "Variance: {}", self.variance())?;
        writeln!(f, "Min: {}", self.min)?;
        writeln!(f, "Max: {}", self.max)?;
        writeln!(f, "Q1: {}", self.tdigest.estimate_quantile(0.25))?;
        writeln!(f, "Median: {}", self.tdigest.estimate_quantile(0.5))?;
        writeln!(f, "Q3: {}", self.tdigest.estimate_quantile(0.75))?;
        writeln!(f, "Frequencies: {:#?}", self.frequencies)?;

        Ok(())
    }
}

impl Merge for FeatureStats {
    fn merge_in_place(&mut self, other: &FeatureStats) {
        let n1 = self.count as f64;
        let n2 = other.count as f64;
        let n = n1 + n2;

        self.count = n as usize;

        let delta = other.mean - self.mean;
        self.mean = self.mean + delta * (n2 / n);
        self.m2 = self.m2 + other.m2 + delta.powi(2) * (n1 * n2 / n);

        self.min = self.min.min(other.min);
        self.max = self.max.max(other.max);

        self.frequencies.iter_mut()
            .zip(other.frequencies.iter())
            .for_each(|(a, b)| *a += b);

        self.tdigest = TDigest::merge_digests(vec![self.tdigest.clone(), other.tdigest.clone()]);
        self.buffer.extend_from_slice(&other.buffer);
        
        if self.buffer.len() >= TDIGEST_BUFFER_SIZE {
            self.flush_buffer();
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct TrafficStats {
    pub stats: HashMap<FeatureKind, Vec<FeatureStats>> 
}

#[derive(Debug)]
pub struct TrafficStatsView<'a> {
    stats: &'a TrafficStats,
    feature: Option<FeatureKind>,
    index: Option<usize>,
}

impl TrafficStats {
    pub fn update(&mut self, flow: &Flow) {
        let flow_length = flow.packets.len();

        for feature in FeatureKind::iter() {
            let stats_vec = self.stats.entry(feature.clone()).or_default();
            if stats_vec.len() < flow_length {
                stats_vec.resize_with(flow_length, FeatureStats::default);
            }

            for (i, packet) in flow.packets.iter().enumerate() {
                stats_vec[i].update(packet.get_feature(&feature));
            }
        }
    }

    pub fn finalize(&mut self) {
        for stats_vec in self.stats.values_mut() {
            for stats in stats_vec.iter_mut() {
                stats.flush_buffer();
            }
        }
    }

    pub fn from_flows(flows: &[Flow]) -> Self {
        let mut traffic_stats = flows.par_iter()
            .map(|flow| {
                let mut stats = Self::default();
                stats.update(flow);
                stats
            })
            .reduce(Self::default, |accumulator, stats| accumulator.merge(stats));
        
        traffic_stats.finalize();

        traffic_stats
    }

    pub fn view(&self) -> TrafficStatsView<'_> {
        TrafficStatsView {
            stats: self,
            feature: None,
            index: None,
        }
    }
}

impl PostcardIO for TrafficStats {}
impl Merge for TrafficStats {
    fn merge_in_place(&mut self, other: &TrafficStats) {
        if self.stats.is_empty() {
            self.stats = other.stats.clone();
            return;
        }

        for (feature, stats) in self.stats.iter_mut() {
            let other_stats = &other.stats[feature];

            let max_len = stats.len().max(other_stats.len());
            stats.resize_with(max_len, FeatureStats::default);

            for (i, other_stat) in other_stats.iter().enumerate() {
                stats[i].merge_in_place(other_stat);
            }
        }
    }
}

impl<'a> TrafficStatsView<'a> {
    pub fn feature(mut self, feature: FeatureKind) -> Self {
        self.feature = Some(feature);
        self
    }

    pub fn index(mut self, index: usize) -> Self {
        self.index = Some(index);
        self
    }
}

impl fmt::Display for TrafficStatsView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.stats.stats.values()
            .next()
            .map(|v| v.len())
            .unwrap_or(0);

        let mut first = true;
        for i in 0..len {
            if let Some(idx) = self.index {
                if i != idx { continue; }
            }

            if !first {
                writeln!(f)?;
            }
            first = false;

            writeln!(f, "=== Index {} ===", i)?;

            for (feature, stats) in &self.stats.stats {
                if let Some(feature_filter) = &self.feature {
                    if *feature != *feature_filter { continue; }
                }

                write!(f, "\n{:?}:\n===\n{}", feature, stats[i])?;
            }
        }

        Ok(())
    }
}

pub fn bin(traffic_stats: TrafficStats, feature_mask: BitFlags<FeatureKind>, markov_order: u32, epsilon: f64, delta: f64) -> Vec<PacketQuantizer> {
    let max_len = traffic_stats
        .stats
        .values()
        .map(|v| v.len())
        .max()
        .unwrap_or(0);
    
    let mut quantizers: Vec<PacketQuantizer> = Vec::with_capacity(max_len);
    
    for i in 0..max_len {
        let mut packet_quantizer = PacketQuantizer::default();
        
        let n = feature_mask.iter()
            .filter_map(|f| traffic_stats.stats.get(&f).and_then(|v| v.get(i)))
            .map(|s| s.count)
            .min()
            .unwrap_or(0);
        let outcome_budget = bins_from_sample_complexity(n, epsilon, delta);
        let mut per_packet_budget = (outcome_budget as f64).powf(1.0 / (markov_order.min(i as u32) + 1) as f64).floor() as u32;

        println!("Index {} | n = {} | k = {} -> {} per packet", i, n, outcome_budget, per_packet_budget);

        if feature_mask.contains(FeatureKind::Direction) {
            per_packet_budget /= 2;
            packet_quantizer.set_feature_quantizer(
                FeatureQuantizer::identity(BoundedFeature::new(FeatureKind::Direction))
            );
            println!("\t{:#?}) nbins: {}", FeatureKind::Direction, 2);
        }

        let mut size_bins = 1;
        if feature_mask.contains(FeatureKind::Size) {
            if let Some(stats) = traffic_stats.stats.get(&FeatureKind::Size).and_then(|v| v.get(i)) {
                let feature = BoundedFeature::new(FeatureKind::Size);
                let fd = freedman_diaconis_rule(&feature, n, stats.iqr());
                
                let time_masked = !feature_mask.contains(FeatureKind::Timestamp);
                let size_budget = if time_masked {
                    per_packet_budget.min(feature.max() as u32)
                } else {
                    (per_packet_budget.isqrt()).min(feature.max() as u32)
                };

                size_bins = if time_masked {
                    // single feature => ignore FD, maximize structure
                    size_budget
                } else {
                    // multiple features => FD can restrict
                    fd.min(size_budget)
                };

                let quantizer = if size_bins < 1460 {
                    FeatureQuantizer::maxdiff(feature, &stats.frequencies, size_bins)
                }
                else {
                    FeatureQuantizer::identity(feature)
                };

                packet_quantizer.set_feature_quantizer(quantizer);
                println!("\t{:#?}) nbins: {}", FeatureKind::Size, size_bins);
            }
        }

        if feature_mask.contains(FeatureKind::Timestamp) {
            if let Some(stats) = traffic_stats.stats.get(&FeatureKind::Timestamp).and_then(|v| v.get(i)) {
                let effective_min = stats.tdigest.estimate_quantile(0.01).max(FeatureKind::Timestamp.domain().min);
                let effective_max = stats.tdigest.estimate_quantile(0.99).min(FeatureKind::Timestamp.domain().max);
                let bounded = BoundedFeature::new_with_bounds(FeatureKind::Timestamp, Some(effective_min), Some(effective_max));

                let time_bins = freedman_diaconis_rule(&bounded, n, stats.iqr()).min(per_packet_budget / size_bins);

                packet_quantizer.set_feature_quantizer(FeatureQuantizer::log_uniform_bounded(bounded, time_bins));
                println!("\t{:#?}) nbins: {} | lower: {} | upper: {}", FeatureKind::Timestamp, time_bins, effective_min, effective_max);
            }
        }

        assert!(
            packet_quantizer.timestamp.num_bins() *
            packet_quantizer.direction.num_bins() *
            packet_quantizer.size.num_bins()
            <= outcome_budget, "exceeded outcome budget");

        quantizers.push(packet_quantizer);
    }

    quantizers
}

// TODO: instead of assertion, return Result so can create stats up to furthest possible packet index
pub fn bins_from_sample_complexity(n: usize, epsilon: f64, delta: f64) -> usize {
    let squared_epsilon = epsilon * epsilon;
    let min_samples = (2.0 / squared_epsilon) * (2.0 / delta).ln();
    assert!(n as f64 >= min_samples, "Not enough samples! Have {}, but need at least {} samples. Relax epsilon and/or delta.", n, min_samples.ceil());
    (n as f64 * squared_epsilon).floor() as usize
}

pub fn scotts_rule(feature: &BoundedFeature, n: usize, sigma: f64) -> u32 {
    if sigma <= 0.0 || feature.effective_max() == feature.min() {
        return 1;
    }

    let width = 3.49 * sigma * (n as f64).powf(-1.0 / 3.0);
    ((feature.effective_max() - feature.effective_min()) / width).ceil() as u32
}

pub fn freedman_diaconis_rule(feature: &BoundedFeature, n: usize, iqr: f64) -> u32 {
    if iqr == 0.0 || feature.effective_max() == feature.effective_min() {
        return 1;
    }

    let width = 2.0 * iqr * (n as f64).powf(-1.0 / 3.0);
    ((feature.effective_max() - feature.effective_min()) / width).ceil() as u32
}

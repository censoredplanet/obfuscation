use std::fmt;

use hashbrown::HashMap;
use tdigest::TDigest;
use enumflags2::BitFlags;

use crate::merge::{Merge, PostcardIO};
use crate::base::Flow;
use crate::feature::{FeatureKind};
use crate::quantization::{BoundedFeature, FeatureQuantizer, PacketQuantizer};

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct FeatureStats {
    pub count: usize,
    pub mean: f64,
    pub m2: f64,
    pub min: f64,
    pub max: f64,
    pub tdigest: TDigest
}

impl FeatureStats {
    pub fn update(&mut self, value: f64) {
        self.count += 1;

        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;

        self.min = self.min.min(value);
        self.max = self.max.max(value);

        self.tdigest = self.tdigest.merge_unsorted(vec![value]);
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

    pub fn iqr(&self) -> f64 {
        self.tdigest.estimate_quantile(0.75) - self.tdigest.estimate_quantile(0.25)
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
            tdigest: TDigest::new_with_size(100)
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

        self.tdigest = TDigest::merge_digests(vec![self.tdigest.clone(), other.tdigest.clone()]);
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
        for (i, packet) in flow.packets.iter().enumerate() {
            for feature in FeatureKind::iter() {
                let vec = self.stats.entry(feature.clone()).or_default();
                if vec.len() <= i {
                    vec.resize_with(i + 1, FeatureStats::default);
                }
                vec[i].update(packet.get_feature(&feature));
            }
        }
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
        let mut feature_bins = Vec::<(BoundedFeature, u32)>::new();
        let mut packet_quantizer = PacketQuantizer::default();
        let mut n = 0;

        for feature in feature_mask.iter() {
            if let Some(stats) = traffic_stats.stats
                .get(&feature)
                .and_then(|v| v.get(i))
            {
                // should be identical across features, but enforce in future
                n = stats.count;

                let bounded_feature = match feature {
                    FeatureKind::Timestamp => {
                        println!("{:#?} {:#?}", stats.tdigest.estimate_quantile(0.01), stats.tdigest.estimate_quantile(0.99));
                        let effective_min = stats.tdigest.estimate_quantile(0.01).max(feature.domain().min);
                        let effective_max = stats.tdigest.estimate_quantile(0.99).min(feature.domain().max);

                        BoundedFeature::new_with_bounds(
                            feature.clone(),
                            Some(effective_min),
                            Some(effective_max),
                        )
                    }
                    _ => BoundedFeature::new(feature.clone()),
                };

                let proposed_bins = propose_feature_bins(&bounded_feature, stats);
                feature_bins.push((bounded_feature, proposed_bins));
            }
        }

        let outcome_budget = bins_from_sample_complexity(n, epsilon, delta);

        greedy_shrink_bins(&mut feature_bins, outcome_budget, markov_order);

        println!("Index {} | N = {} | k = {}", i, n, outcome_budget);
        for (feature, num_bins) in feature_bins.into_iter() {
            let feature_quantizer = match feature.feature() {
                FeatureKind::Direction => FeatureQuantizer::identity(feature),
                _ => FeatureQuantizer::uniform_bounded(feature, num_bins)
            };
            println!("\t{:#?}) nbins: {} | bin_width: {} | lower: {} | upper: {}", 
                &feature_quantizer.feature.feature(),
                &feature_quantizer.num_bins(), 
                &feature_quantizer.bin_width(),
                &feature_quantizer.feature.effective_min(),
                &feature_quantizer.feature.effective_max()
            );
            packet_quantizer.set_feature_quantizer(feature_quantizer);
        }

        quantizers.push(packet_quantizer);
    }

    quantizers
}

pub fn propose_feature_bins(feature: &BoundedFeature, stats: &FeatureStats) -> u32 {
    match feature.feature() {
        FeatureKind::Timestamp | FeatureKind::Entropy => freedman_diaconis_rule(&feature, stats.count, stats.iqr()),
        FeatureKind::Size => freedman_diaconis_rule(&feature, stats.count, stats.iqr()).max(feature.domain_size() as u32),
        FeatureKind::Direction => feature.domain_size() as u32
    }
}

pub fn greedy_shrink_bins(
    feature_bins: &mut Vec<(BoundedFeature, u32)>,
    outcome_budget: usize,
    markov_order: u32) 
{
    loop {
        let num_outcomes = (feature_bins
            .iter()
            .map(|(_, k)| *k as usize)
            .product::<usize>()).pow(markov_order + 1);

        if num_outcomes <= outcome_budget {
            break;
        }

        // Find feature with largest K > 1
        if let Some((_, k)) = feature_bins
            .iter_mut()
            .filter(|(_, k)| *k > 1)
            .max_by_key(|(_, k)| *k)
        {
            *k -= 1;
        } 
        else {
            // All bins have size 1, cannot shrink further
            break;
        }
    }
}

pub fn bins_from_sample_complexity(n: usize, epsilon: f64, delta: f64) -> usize {
    let k = n as f64 * (epsilon * epsilon);
    assert!(k >= 2.0 * (2.0 / delta).ln(), "Not enough samples! Relax epsilon and/or delta.");
    k.floor() as usize
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

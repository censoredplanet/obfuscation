use std::fmt;

use hashbrown::HashMap;

use crate::merge::{Merge, PostcardIO};

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq, std::hash::Hash)]
pub struct Sequence<T: Clone> {
    pub sequence: Box<[T]>
}

impl<T: Clone> Sequence<T> {
    pub fn prefix(&self) -> Self {
        Sequence {
            sequence: self.sequence[0..(self.sequence.len() - 1)].into()
        }
    }

    pub fn last(&self) -> T {
        self.sequence[self.sequence.len() - 1].clone()
    }
}

impl<T: fmt::Display + Clone> fmt::Display for Sequence<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<")?;
        for (idx, element) in self.sequence.iter().enumerate() {
            if idx > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", element)?;
        }
        write!(f, ">")
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
#[serde(bound(
    serialize = "K: serde::Serialize + Eq + std::hash::Hash",
    deserialize = "K: serde::de::DeserializeOwned + Eq + std::hash::Hash + Clone"
))]
pub struct Histogram<K: Eq + std::hash::Hash + Clone> {
    pub counts: HashMap<Sequence<K>, usize>,
    total: usize,
    alpha: f64,
    alphabet_size: usize,
    sequence_len: usize
}

impl<K> Histogram<K>
where
    K: serde::Serialize + Eq + std::hash::Hash + Clone,
{
    pub fn new(alphabet_size: usize, sequence_len: usize, pseudocount: f64) -> Self {
        Self { 
            counts: HashMap::new(),
            total: 0,
            alpha: pseudocount,
            alphabet_size: alphabet_size,
            sequence_len: sequence_len
        }
    }

    pub fn empty_like(&self) -> Self {
        Histogram::new(self.alphabet_size, self.sequence_len, self.alpha)
    }

    fn increment_by(&mut self, key: Sequence<K>, amount: usize) -> () {
        *self.counts.entry(key).or_insert(0) += amount;
        self.total += amount;
    }

    pub fn increment(&mut self, key: Sequence<K>) -> () {
        self.increment_by(key, 1);
    }

    pub fn support_size(&self) -> usize {
        self.counts.len()
    }

    pub fn domain_size(&self) -> usize {
        self.alphabet_size.pow(self.sequence_len as u32)
    }

    pub fn conditional_histogram(&self) -> HashMap<Sequence<K>, Histogram<K>> {
        let mut conditionals: HashMap<Sequence<K>, Histogram<K>> = HashMap::new();
        
        for (sequence, count) in self.counts.iter() {
            let prefix = sequence.prefix();
            let last = Sequence {
                sequence: vec![sequence.last()].into()
            };

            let histogram = conditionals
                .entry(prefix)
                .or_insert_with(|| Histogram::new(self.alphabet_size, 1, self.alpha));
            
            *histogram.counts.entry(last).or_insert(0) += count;
            histogram.total += count;
        }

        conditionals
    }

    pub fn get_count(&self, key: &Sequence<K>) -> usize {
        *self.counts.get(key).unwrap_or(&0)
    }

    // TODO: eventually introduce ProbabilityDistribution type so that different smoothing
    // choices don't require rebuilding histograms
    pub fn empirical_probability(&self, x: &Sequence<K>) -> f64 {
        let count = *self.counts.get(x).unwrap_or(&0);
        count as f64 / self.total as f64
    }

    pub fn smoothed_probability(&self, x: &Sequence<K>) -> f64 {
        let count = *self.counts.get(x).unwrap_or(&0);
        (count as f64 + self.alpha) / (self.total as f64 + self.alpha * self.domain_size() as f64)
    }

    pub fn prefix_counts(&self) -> HashMap<Sequence<K>, usize> {
        let mut prefix_counts = HashMap::new();

        for (key, count) in self.counts.iter() {
            let prefix = key.prefix();
            *prefix_counts.entry(prefix).or_insert(0) += *count;
        }

        prefix_counts
    }

    pub fn kl_divergence(&self, other: &Histogram<K>) -> HashMap<Sequence<K>, f64> 
    where 
        K: Eq + std::hash::Hash + Clone
    {
        let mut contributions = HashMap::new();

        for x in self.counts.keys() {
            let p = self.empirical_probability(x);
            let q = other.smoothed_probability(x);
            
            let contribution = p * (p / q).ln();
            contributions.insert(x.clone(), contribution);
        }
        
        contributions
    }

    pub fn conditional_kl_divergence(&self, other: &Histogram<K>) -> HashMap<Sequence<K>, f64> {
        let p_prefix_counts = self.prefix_counts();
        let q_prefix_counts = other.prefix_counts();

        let mut contributions = HashMap::new();

        for x in self.counts.keys() {
            let prefix = x.prefix();

            let p = self.get_count(x);
            let p_prefix = *p_prefix_counts.get(&prefix).unwrap();
            let p_given_prefix = (p as f64) / (p_prefix as f64);

            let q = other.get_count(x);
            let q_prefix = *q_prefix_counts.get(&prefix).unwrap_or(&0);
            let q_given_prefix = (q as f64 + other.alpha) / (q_prefix as f64 + (other.alphabet_size as f64 * other.alpha));
            
            let contribution = self.empirical_probability(x) * (p_given_prefix / q_given_prefix).ln();
            contributions.insert(x.clone(), contribution);
        }
        
        contributions        
    }
}

impl<K: Eq + std::hash::Hash + Clone> Merge for Histogram<K> {
    fn merge_in_place(&mut self, other: &Histogram<K>) {
        for (k, v) in other.counts.iter() {
            *self.counts.entry(k.clone()).or_insert(0) += v;
        }

        self.total += other.total;
    }
}

impl<K: serde::Serialize + Eq + std::hash::Hash + Clone + fmt::Display> fmt::Display for Histogram<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut items: Vec<_> = self.counts.iter().collect();
        items.sort_by_key(|&(_, c)| std::cmp::Reverse(*c));

        writeln!(f, "{:<10}\t{:<12}\t{}", "Count", "Prob", "Sequence")?;
        for (key, count) in items {
            let probability = self.empirical_probability(key);
            writeln!(f, "{:<10}\t{:<12.4}\t{}", count, probability, key)?;
        }

        writeln!(f, "[Support Size: {} | # Observations: {}]", self.support_size(), self.total)?;

        Ok(())
    }
}

impl<T> PostcardIO for Vec<Histogram<T>>
where
    T: serde::Serialize + serde::de::DeserializeOwned + Eq + std::hash::Hash + Clone,
{}

pub fn merge_histogram_vecs<K>(accumulator: &mut Vec<Histogram<K>>, histograms: &[Histogram<K>])
where
    K: serde::Serialize + serde::de::DeserializeOwned + Eq + std::hash::Hash + Clone
{
    for i in accumulator.len()..histograms.len() {
        accumulator.push(histograms[i].empty_like());
    }

    for (idx, histogram) in histograms.iter().enumerate() {
        accumulator[idx].merge_in_place(histogram);
    }
}

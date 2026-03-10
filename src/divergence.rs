//use crate::merge::*;
use crate::quantization::PacketProjection;
use crate::histograms::{Histogram, merge_histogram_vecs};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TrafficProfile {
    pub profile: Vec<Histogram<PacketProjection>>,
    pub markov_order: usize
}

impl TrafficProfile {
    pub fn empty(markov_order: usize) -> Self {
        Self {
            profile: Vec::new(),
            markov_order
        }
    }
    // TODO: confirm w/ Josh
    pub fn divergence(&self, other: &TrafficProfile) -> Divergence {
        let mut kl = Vec::with_capacity(self.profile.len());

        for (i, (p, q)) in std::iter::zip(&self.profile, &other.profile).enumerate() {
            if i < self.markov_order {
                kl.push(p.kl_divergence(q));
            }
            else {
                let p_prefix = p.prefix_histogram();
                let q_prefix = q.prefix_histogram();

                kl.push(p.kl_divergence(q) - p_prefix.kl_divergence(&q_prefix));
            }
        }

        Divergence {
            vector: kl.into_boxed_slice(),
            markov_order: self.markov_order
        }
    }
}

impl PostcardIO for TrafficProfile {}

impl Merge for TrafficProfile {
    fn merge_in_place(&mut self, other: &Self) {
        assert_eq!(self.markov_order, other.markov_order);
        merge_histogram_vecs(&mut self.profile, &other.profile);
    }
}

#[derive(Debug)]
pub struct Divergence {
   pub vector: Box<[f64]>,
   pub markov_order: usize
}

impl Divergence {
    pub fn argmax(&self) -> usize {
        assert!(!self.vector.is_empty());

        self.vector
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.total_cmp(b))
            .map(|(index, _)| index)
            .unwrap()
    }

    pub fn sum(&self) -> f64 {
        self.vector.iter().sum()
    }
}

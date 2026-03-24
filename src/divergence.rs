use std::marker::PhantomData;

use crate::merge::*;
use crate::quantization::PacketProjection;
use crate::histograms::{Histogram, merge_histogram_vecs};

#[derive(Debug)]
pub struct Left;
#[derive(Debug)]
pub struct Right;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TrafficProfile {
    pub profile: Vec<Histogram<PacketProjection>>,
    pub markov_order: u32
}

impl TrafficProfile {
    pub fn empty(markov_order: u32) -> Self {
        Self {
            profile: Vec::new(),
            markov_order
        }
    }

    fn kl(left: &TrafficProfile, right: &TrafficProfile) -> Vec<f64> {
        let mut kl = Vec::with_capacity(left.profile.len());

        for (i, (p, q)) in std::iter::zip(&left.profile, &right.profile).enumerate() {
            if i < left.markov_order as usize {
                kl.push(p.kl_divergence(q));
            }
            else {
                let p_prefix = p.prefix_histogram();
                let q_prefix = q.prefix_histogram();

                kl.push(p.kl_divergence(q) - p_prefix.kl_divergence(&q_prefix));
            }
        }

        kl
    }
    
    pub fn kl_divergence(&self, right: &TrafficProfile) -> KLDivergence<Left, Right> {
        KLDivergence {
            divergence: Divergence {
                vector: Self::kl(self, right).into_boxed_slice(),
                markov_order: self.markov_order
            },
            _marker: PhantomData
        }
    }

    pub fn reverse_kl_divergence(&self, left: &TrafficProfile) -> KLDivergence<Right, Left> {
        KLDivergence {
            divergence: Divergence {
                vector: Self::kl(left, self).into_boxed_slice(),
                markov_order: self.markov_order
            },
            _marker: PhantomData
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
   pub markov_order: u32
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

    pub fn sum_until(&self, i: usize) -> f64 {
        assert!(i < self.vector.len(), "Index {} out of bounds!", i);

        if i < self.markov_order as usize {
            self.vector[i]
        }
        else {
            self.vector[(self.markov_order as usize)..=i].iter().sum()
        }
    }

    pub fn sum(&self) -> f64 {
        self.sum_until(self.vector.len() - 1)
    }

    pub fn cumulative_sum(&self) -> Box<[f64]> {
        (0..self.vector.len())
            .map(|i| self.sum_until(i))
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }
}

#[derive(Debug)]
pub struct KLDivergence<P, Q> {
    divergence: Divergence,
    _marker: PhantomData<(P, Q)>,
}

impl<P, Q> KLDivergence<P, Q> {
    fn error_decay(&self, n: usize) -> Box<[f64]> {
        self.divergence.cumulative_sum()
            .into_iter()
            .map(|v| (-(n as f64) * v).exp())
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }
}

// TODO: refactor common logic into helper function
impl KLDivergence<Left, Right> {
    pub fn cumulative_sum(&self) -> Box<[f64]> {
        self.divergence.cumulative_sum()
    }
    
    pub fn pinsker(&self) -> Box<[f64]> {
        self.divergence.cumulative_sum()
            .into_iter()
            .map(|v| (v / 2.0).sqrt())
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    pub fn bretagnolle_huber(&self) -> Box<[f64]> {
        self.divergence.cumulative_sum()
            .into_iter()
            .map(|v| (1.0 - (-v).exp()).sqrt())
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    pub fn bayes_error_lower_bound(&self) -> Box<[f64]> {
        std::iter::zip(self.pinsker(), self.bretagnolle_huber())
            .map(|(a, b)| (1.0 - a.min(b)) / 2.0)
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    pub fn chernoff_stein_lemma(&self, n: usize) -> Box<[f64]> {
        self.error_decay(n)
    }
}

impl KLDivergence<Right, Left> {
    pub fn sanovs_theorem(&self, n: usize) -> Box<[f64]> {
        self.error_decay(n)
    }
}

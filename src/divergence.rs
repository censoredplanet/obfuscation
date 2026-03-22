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
    pub markov_order: usize
}

impl TrafficProfile {
    pub fn empty(markov_order: usize) -> Self {
        Self {
            profile: Vec::new(),
            markov_order
        }
    }

    fn kl(left: &TrafficProfile, right: &TrafficProfile) -> Vec<f64> {
        let mut kl = Vec::with_capacity(left.profile.len());

        for (i, (p, q)) in std::iter::zip(&left.profile, &right.profile).enumerate() {
            if i < left.markov_order {
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

    pub fn sum_until(&self, i: usize) -> f64 {
        assert!(i < self.vector.len(), "Index {} out of bounds!", i);

        if i < self.markov_order {
            self.vector[i]
        }
        else {
            self.vector[self.markov_order..=i].iter().sum()
        }
    }

    pub fn sum(&self) -> f64 {
        self.sum_until(self.vector.len() - 1)
    }
}

#[derive(Debug)]
pub struct KLDivergence<P, Q> {
    divergence: Divergence,
    _marker: PhantomData<(P, Q)>,
}

// TODO: refactor common logic into helper function
impl KLDivergence<Left, Right> {
    pub fn pinsker(&self) -> Box<[f64]> {
        (0..self.divergence.vector.len())
            .map(|i| (0.5 * self.divergence.sum_until(i)).sqrt())
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    pub fn bretagnolle_huber(&self) -> Box<[f64]> {
        (0..self.divergence.vector.len())
            .map(|i| (1.0 - (-self.divergence.sum_until(i)).exp()).sqrt())
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }
}

impl KLDivergence<Right, Left> {
    pub fn sanovs_theorem(&self, n: usize) -> Box<[f64]> {
        (0..self.divergence.vector.len())
            .map(|i| (-(n as f64) * self.divergence.sum_until(i)).exp())
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }
}

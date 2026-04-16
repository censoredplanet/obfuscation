use std::marker::PhantomData;

use hashbrown::HashMap;

use crate::merge::*;
use crate::quantization::PacketProjection;
use crate::histograms::{Histogram, merge_histogram_vecs, Sequence, SequenceDisplay};

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

    fn compute_kl_terms(left: &TrafficProfile, right: &TrafficProfile) -> Vec<HashMap<Sequence<PacketProjection>, f64>> {
        let mut kl = Vec::with_capacity(left.profile.len());

        for (i, (p, q)) in std::iter::zip(&left.profile, &right.profile).enumerate() {
            if i < left.markov_order as usize {
                kl.push(p.kl_divergence(q))
            }
            else {
                kl.push(p.conditional_kl_divergence(q));
            }
        }

        kl
    }
    
    pub fn kl_divergence(&self, right: &TrafficProfile) -> KLDivergence<Left, Right> {
        KLDivergence {
            divergence: Divergence {
                terms: Self::compute_kl_terms(self, right).into_boxed_slice(),
                markov_order: self.markov_order
            },
            _marker: PhantomData
        }
    }

    pub fn reverse_kl_divergence(&self, left: &TrafficProfile) -> KLDivergence<Right, Left> {
        KLDivergence {
            divergence: Divergence {
                terms: Self::compute_kl_terms(left, self).into_boxed_slice(),
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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Divergence {
    pub terms: Box<[HashMap<Sequence<PacketProjection>, f64>]>,
    pub markov_order: u32
}

impl Divergence {
    fn per_index_divergence(&self) -> Box<[f64]> {
        let index_sums = self.terms.iter()
            .map(|m| m.values().sum())
            .collect::<Vec<f64>>();
        
        (0..index_sums.len())
            .map(|i| {
                if i > 0 && i < self.markov_order as usize {
                    index_sums[i] - index_sums[i - 1]
                } 
                else {
                    index_sums[i]
                }
            })
            .collect()
    }

    fn cumulative_divergence(&self) -> Box<[f64]> {
        let index_terms = self.per_index_divergence();
        let mut sum = 0.0;

        index_terms.iter()
            .map(|e| {
                sum += e;
                sum.max(0.0)
            })
            .collect()
    }

    pub fn total_divergence(&self) -> f64 {
        self.per_index_divergence().iter().sum()
    }

    pub fn max_index(&self) -> usize {
        self.per_index_divergence()
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.total_cmp(b))
            .map(|(index, _)| index)
            .unwrap()
    }

    pub fn max_packet_at_idx(&self, idx: usize) {
        let mut sorted_terms = self.terms[idx]
            .iter()
            .collect::<Vec<_>>();
        
        sorted_terms.sort_by(|(_, a), (_, b)| a.total_cmp(b));
        
        for (sequence, contribution) in sorted_terms {
            let sequence_display = SequenceDisplay {
                sequence: sequence,
                quantizer: None
            };
            println!("{} {}", sequence_display, contribution);
        }
    }
}

impl PostcardIO for Divergence {}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct KLDivergence<P, Q> {
    divergence: Divergence,
    _marker: PhantomData<(P, Q)>,
}

impl<P, Q> KLDivergence<P, Q> {
    fn error_decay(&self, n: usize) -> Box<[f64]> {
        self.divergence.cumulative_divergence()
            .into_iter()
            .map(|v| (-(n as f64) * v).exp())
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }
}

// TODO: refactor common logic into helper function
impl KLDivergence<Left, Right> {
    pub fn cumulative_divergence(&self) -> Box<[f64]> {
        self.divergence.cumulative_divergence()
    }

    pub fn per_index_divergence(&self) -> Box<[f64]> {
        self.divergence.per_index_divergence()
    }

    pub fn max_index(&self) -> usize {
        self.divergence.max_index()
    }

    pub fn max_packet_at_idx(&self, idx: usize) {
        self.divergence.max_packet_at_idx(idx)
    }
    
    pub fn pinsker(&self) -> Box<[f64]> {
        self.divergence.cumulative_divergence()
            .into_iter()
            .map(|v| (v / 2.0).sqrt())
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    pub fn bretagnolle_huber(&self) -> Box<[f64]> {
        self.divergence.cumulative_divergence()
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

impl<P, Q> PostcardIO for KLDivergence<P, Q> {}

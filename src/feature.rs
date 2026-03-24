use std::str::FromStr;

use serde::{Serialize, Deserialize};
use enumflags2::{bitflags};

use crate::base::MSS;

#[bitflags]
#[repr(u8)]
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Hash)]
pub enum FeatureKind {
    Timestamp,
    Direction,
    Size,
    Entropy,
}

impl FromStr for FeatureKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "timestamp" => Ok(Self::Timestamp),
            "direction" => Ok(Self::Direction),
            "size" => Ok(Self::Size),
            "entropy" => Ok(Self::Entropy),
            _ => Err(format!("invalid feature: {}", s)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RandomVariableDomain {
    pub min: f64,
    pub max: f64
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FeatureValueType {
    Continuous,
    Discrete,
}

impl FeatureKind {
    pub fn iter() -> impl Iterator<Item = FeatureKind> {
        [
            FeatureKind::Timestamp,
            FeatureKind::Direction,
            FeatureKind::Size,
            FeatureKind::Entropy,
        ]
        .into_iter()
    }

    pub fn domain(&self) -> RandomVariableDomain {
        match &self {
            FeatureKind::Timestamp => RandomVariableDomain { min: 0.0, max: f64::INFINITY },
            FeatureKind::Direction => RandomVariableDomain { min: 0.0, max: 1.0 },
            FeatureKind::Size      => RandomVariableDomain { min: 1.0,  max: MSS as f64 },
            FeatureKind::Entropy   => RandomVariableDomain { min: 0.0,  max: 8.0 },
        }
    }

    pub fn value_type(&self) -> FeatureValueType {
        match &self {
            FeatureKind::Timestamp | FeatureKind::Entropy => FeatureValueType::Continuous,
            FeatureKind::Direction | FeatureKind::Size => FeatureValueType::Discrete,
        }
    }
}

pub trait EmitFeatures {
    type Value;

    fn id(&self) -> &Vec<u8>;
    fn emit_features(&self, num_packets: usize, emitter: &mut dyn FeatureEmitter<Self::Value>);
}

pub trait FeatureEmitter<T> {
    fn push_feature(&mut self, value: T);
    fn push_label(&mut self, label: usize);
}

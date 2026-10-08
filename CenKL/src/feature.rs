use std::str::FromStr;

use enumflags2::bitflags;
use serde::{Deserialize, Serialize};

use crate::base::MSS;
use crate::quantization::FlowQuantizer;

#[bitflags]
#[repr(u8)]
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Hash)]
pub enum FeatureKind {
    Timestamp,
    Direction,
    Size,
}

impl FromStr for FeatureKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "timestamp" => Ok(Self::Timestamp),
            "direction" => Ok(Self::Direction),
            "size" => Ok(Self::Size),
            _ => Err(format!("invalid feature: {}", s)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RandomVariableDomain {
    pub min: f64,
    pub max: f64,
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
        ]
        .into_iter()
    }

    pub fn domain(&self) -> RandomVariableDomain {
        match &self {
            FeatureKind::Timestamp => RandomVariableDomain {
                min: 0.0,
                max: f64::INFINITY,
            },
            FeatureKind::Direction => RandomVariableDomain { min: 0.0, max: 1.0 },
            FeatureKind::Size => RandomVariableDomain {
                min: 1.0,
                max: MSS as f64,
            },
        }
    }

    pub fn value_type(&self) -> FeatureValueType {
        match &self {
            FeatureKind::Timestamp => FeatureValueType::Continuous,
            FeatureKind::Direction | FeatureKind::Size => FeatureValueType::Discrete,
        }
    }
}

pub trait EmitFeatures {
    type Value;

    fn id(&self) -> &Vec<u8>;
    fn emit_features(
        &self,
        num_packets: usize,
        quantizer: &FlowQuantizer,
        emitter: &mut dyn FeatureEmitter<Self::Value>,
    );
}

pub trait FeatureEmitter<T> {
    fn push_feature(&mut self, value: T);
    fn push_label(&mut self, label: usize);
}

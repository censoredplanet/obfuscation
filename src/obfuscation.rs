use std::collections::VecDeque;

use serde::{Serialize, Deserialize};
use rv::prelude::*;
use rayon::prelude::*;

use crate::base::{Packet, ProtocolMetadata, Flow};
use crate::feature::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum DistributionFamily {
    Fixed(f64),
    Uniform { min: f64, max: f64 },
    Normal { mu: f64, sigma: f64 },
    Exponential { lambda: f64, shift: f64 }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum TruncationMode {
    Full,
    Truncated
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Sampler {
    pub distribution: DistributionFamily,
    pub domain: RandomVariableDomain,
    pub support_type: FeatureValueType,
    pub truncation: TruncationMode,
}

impl Sampler {
    pub fn sample<R: rand::Rng>(&self, rng: &mut R) -> f64 {
        let mut sample = match &self.distribution {
            DistributionFamily::Fixed(value) => *value,
            DistributionFamily::Uniform { min, max } => {
                let distribution = Uniform::new(*min, *max).unwrap();
                distribution.draw(rng)
            }
            DistributionFamily::Normal { mu, sigma } => {
                let distribution = Gaussian::new(*mu, *sigma).unwrap();
                distribution.draw(rng)   
            },
            DistributionFamily::Exponential { lambda, shift } => {
                let distribution = Exponential::new(*lambda).unwrap();
                let x: f64 = distribution.draw(rng);
                x - *shift
            }
        };

        if let FeatureValueType::Discrete = self.support_type {
            sample = sample.round();
        }

        sample.clamp(self.domain.min, self.domain.max)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum TransformRule {
    Delta(Sampler),
    Absolute(Sampler)
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct RuleCondition {
    pub indices: Option<std::ops::Range<usize>>,
    pub c2s_indices: Option<std::ops::Range<usize>>,
    pub s2c_indices: Option<std::ops::Range<usize>>,
    pub ssl_established: Option<bool>,
}

impl RuleCondition {
    pub fn matches(&self, packet: &Packet, ctx: &PacketContext) -> bool {
        if let Some(r) = &self.indices {
            if !r.contains(&ctx.index) {
                return false;
            }
        }

        match packet.direction.round() as u8 {
            0 => {
                if let Some(r) = &self.s2c_indices {
                    if !r.contains(&ctx.server_index) {
                        return false;
                    }
                }
            }
            1 => {
                if let Some(r) = &self.c2s_indices {
                    if !r.contains(&ctx.client_index) {
                        return false;
                    }
                }
            }
            _ => unreachable!(), // direction is always 0 or 1
        }

        // 3. SSL establishment filter
        if let Some(required) = self.ssl_established {
            if ctx.is_handshake_packet != required {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Rule {
    pub timestamp: Option<TransformRule>,
    pub direction: Option<Sampler>,
    pub size: Option<TransformRule>,
    pub entropy: Option<Sampler>
}

impl Rule {
    pub fn apply<R: rand::Rng>(&self, packet: &Packet, rng: &mut R) -> (Packet, Option<Packet>) {
        let target_timestamp = match &self.timestamp {
            None => packet.timestamp,
            Some(TransformRule::Delta(d)) => packet.timestamp + d.sample(rng),
            Some(TransformRule::Absolute(d)) => d.sample(rng)
        };
        let target_direction = self.direction.as_ref().map_or(packet.direction, |d| d.sample(rng));
        let target_size = match &self.size {
            None => packet.size,
            Some(TransformRule::Delta(d)) => {
                let size_domain = FeatureKind::Size.domain();
                (packet.size + d.sample(rng)).clamp(size_domain.min, size_domain.max)
            },
            Some(TransformRule::Absolute(d)) => d.sample(rng)
        };
        let target_entropy = self.entropy.as_ref().map_or(packet.entropy, |d| d.sample(rng));

        // If we do not have data we can delay at the target endpoint, then we need to
        // insert a dummy packet.
        if packet.timestamp > target_timestamp || packet.direction != target_direction {
            return (Packet {
                timestamp: target_timestamp,
                direction: target_direction,
                size: target_size,
                entropy: target_entropy // always possible under any size as long as all data is junk
            }, Some(packet.clone()));
        }
        else if packet.size <= target_size {
            // Pad packet to target size. No "leftover" packet.
            return (Packet {
                timestamp: target_timestamp,
                direction: target_direction,
                size: target_size,
                entropy: target_entropy // TODO: check that entropy can be satisfied
            }, None);
        }
        else {
            // If packet size is smaller than target size, the packet must be split
            // in two. The first packet receives all of the target properties, while
            // the second packet retains the payload size and entropy properties of
            // the original packet (until it undergoes obfuscation).
            return (Packet {
                timestamp: target_timestamp,
                direction: target_direction,
                size: target_size,
                entropy: target_entropy // TODO: check that entropy can be satisfied
            }, Some(Packet {
                timestamp: target_timestamp,
                direction: target_direction,
                size: packet.size - target_size,
                entropy: packet.entropy
            }));
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConditionalRule {
    pub condition: RuleCondition,
    pub rule: Rule
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum DurationPolicy {
    MatchOriginalCount,
    MaxTicks(usize)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(try_from = "String")]
pub enum TLSMode {
    Outer,      // Preserve existing handshake; obfuscate only post-handshake data
    Inner,      // Ignore handshake; treat entire flow as data
    TLSInTLS,   // Prepend sampled outer handshake; preserve inner TLS; Vision mode
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Obfuscator {
    pub rules: Vec<ConditionalRule>,
    pub default: Rule,
    pub duration: DurationPolicy,
    pub tls_mode: TLSMode
}

#[derive(Debug, Clone)]
pub struct FlowContext {
    pub ssl_est: Option<usize>
}

#[derive(Debug, Clone)]
pub struct PacketContext {
    pub is_handshake_packet: bool,
    pub index: usize,
    pub client_index: usize,
    pub server_index: usize
}

impl Obfuscator {
    pub fn random(mode: TLSMode) -> Self {
        let default_rule = Rule {
            timestamp: Some(TransformRule::Delta(
                RandomDistribution.generate(
                    // max inter-arrival time delay allowed by obfs4:
                    // https://github.com/Yawning/obfs4/blob/master/transports/obfs4/obfs4.go#L563
                    RandomVariableDomain { min: -0.01, max: 0.01 },
                    FeatureKind::Timestamp.value_type(),
                    &mut rand::rng()
            ))),
            direction: None,
            size: Some(TransformRule::Absolute(
                RandomDistribution.generate(
                    FeatureKind::Size.domain(),
                    FeatureKind::Size.value_type(),
                    &mut rand::rng()
            ))),
            entropy: None,
        };

        let mut first_packet_rule = default_rule.clone();
        first_packet_rule.timestamp = None;

        Obfuscator {
            rules: vec![
                ConditionalRule {
                    condition: RuleCondition {
                        indices: Some(0..1),
                        c2s_indices: None,
                        s2c_indices: None,
                        ssl_established: None
                    },
                    rule: first_packet_rule
                }
            ],
            default: default_rule,
            duration: DurationPolicy::MatchOriginalCount,
            tls_mode: mode
        }
    }

    // TODO: better than O(rules)
    fn select_rule(&self, packet: &Packet, packet_ctx: &PacketContext) -> &Rule {
        for rule in &self.rules {
            if rule.condition.matches(packet, packet_ctx) {
                return &rule.rule;
            }
        }

        &self.default
    }

    pub fn obfuscate(&self, packets: &[Packet], flow_ctx: &FlowContext) -> Vec<Packet> {
        let mut rng = rand::rng();

        let mut queue = VecDeque::from(packets.to_vec());
        let mut obfuscated = Vec::new();

        let mut prev_timestamp = 0.0;

        let timesteps = match &self.duration {
            DurationPolicy::MatchOriginalCount => packets.len(),
            DurationPolicy::MaxTicks(timestep) => *timestep
        };
        let mut client_index = 0;
        let mut server_index = 0;
        
        // We do not loop until queue is empty because ability to
        // insert dummy packets does not guarantee queue size shrinks
        for timestep in 0..timesteps {
            // if there is no packet, we can insert a dummy packet,
            // but only if the dummy packet is drawn from a distribution
            let Some(mut packet) = queue.pop_front() else { break; };

            packet.timestamp = packet.timestamp.max(prev_timestamp); // enforce timestamp monotonicity

            let packet_ctx = PacketContext {
                is_handshake_packet: match flow_ctx.ssl_est {
                    Some(ssl_est) => timestep <= ssl_est,
                    None => false,
                },
                index: timestep,
                client_index: client_index,
                server_index: server_index
            };

            let (mut emitted, requeue) = self.select_rule(&packet, &packet_ctx)
                                        .apply(&packet, &mut rng);

            // enforce timestamp monotonicity (if we emitted a dummy packet, its timestamp
            // is less than packet timestamp, but make sure it is not also less than
            // prev_timestamp)
            emitted.timestamp = emitted.timestamp.max(prev_timestamp);

            obfuscated.push(emitted);

            if let Some(leftover) = requeue {
                queue.push_front(leftover);
            }

            prev_timestamp = emitted.timestamp;
            match packet.direction as u8 {
                0 => server_index += 1,
                1 => client_index += 1,
                _ => unreachable!()
            }
        }
        
        obfuscated
    }

    pub fn obfuscate_flow(&self, flow: &Flow) -> Flow {
        let mut obfuscated = flow.clone();

        match (&flow.proto, &self.tls_mode) {
            (ProtocolMetadata::TLSMetadata { ssl_est, .. }, TLSMode::Outer) => {
                let handshake = &obfuscated.packets[..=*ssl_est];
                let data = &obfuscated.packets[(*ssl_est + 1)..];

                let obfuscated_data = self.obfuscate(data, &FlowContext { ssl_est: None });
                
                obfuscated.packets = [handshake, &obfuscated_data].concat();
            },
            (ProtocolMetadata::TLSMetadata { ssl_est, .. }, TLSMode::Inner) => {
                obfuscated.packets = self.obfuscate(&obfuscated.packets, &FlowContext { ssl_est: Some(*ssl_est) });
                obfuscated.proto = ProtocolMetadata::Raw;
            }
            (ProtocolMetadata::Raw, _) => {
                obfuscated.packets = self.obfuscate(&obfuscated.packets, &FlowContext { ssl_est: None });
            },
            (_, _) => todo!()
        };

        obfuscated
    }

    pub fn obfuscate_flows<'a>(&self, flows: &[Flow]) -> Vec<Flow> {
        flows.par_iter().map(|flow| self.obfuscate_flow(flow)).collect()
    }
}

// ==================================================
// Code for generating RANDOM obfuscation protocols
// ==================================================

pub struct RandomDistribution;

impl RandomDistribution {
    // TODO: make the closures functions
    pub fn generate<R: rand::Rng>(&self, domain: RandomVariableDomain, value_type: FeatureValueType, rng: &mut R) -> Sampler {
        let build_random_fixed = |rng: &mut R| {
            let value = rng.random_range(domain.min..domain.max);

            DistributionFamily::Fixed(value)
        };
        
        let build_random_uniform = |rng: &mut R| {
            let a = rng.random_range(domain.min..domain.max);
            let b = rng.random_range(domain.min..domain.max);

            DistributionFamily::Uniform { min: a.min(b), max: a.max(b) }
        };
        
        let build_random_normal = |rng: &mut R| {
            let mu = rng.random_range(domain.min..domain.max);
            let dist_to_min = mu - domain.min;
            let dist_to_max = domain.max - mu;
            let sigma = dist_to_min.max(dist_to_max) / 3.0;

            DistributionFamily::Normal { mu: mu, sigma: sigma }
        };

        let build_random_exponential = |rng: &mut R| {
            let width = domain.max - domain.min;
            let lambda = rng.random_range(1.0 / width..5.81 / width);

            DistributionFamily::Exponential { lambda: lambda, shift: -domain.min }
        };

        Sampler {
            distribution: match rng.random_range(0..4) {
                0 => build_random_fixed(rng),
                1 => build_random_uniform(rng),
                2 => build_random_normal(rng),
                3 => build_random_exponential(rng),
                _ => unreachable!()
            },
            domain: domain,
            support_type: value_type,
            truncation: TruncationMode::Full
        }
    }
}

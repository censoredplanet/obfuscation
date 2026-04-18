use std::error::Error;

use rand::distr::Distribution;
use rand::distr::weighted::WeightedIndex;
use hashbrown::HashMap;

use crate::base::{Flow, FlowMetadata, Packet, ProtocolMetadata};
use crate::quantization::{FlowQuantizer, PacketProjection};
use crate::histograms::{Sequence, Histogram};

#[derive(Debug)]
pub struct WeightedSampler<K: Eq + std::hash::Hash + Clone> {
    pub elements: Vec<K>,
    pub weighted_index: WeightedIndex<usize>
}

impl<K: Eq + std::hash::Hash + Clone> WeightedSampler<K> {
    pub fn sample<R: rand::Rng>(&self, rng: &mut R) -> &K {
        &self.elements[self.weighted_index.sample(rng)]
    }
}

impl<K> From<&Histogram<K>> for WeightedSampler<K> 
where 
    K: serde::Serialize + Eq + std::hash::Hash + Clone
{
    fn from(hist: &Histogram<K>) -> Self {
        let mut elements = Vec::with_capacity(hist.support_size());
        let mut weights = Vec::with_capacity(hist.support_size());

        for (e, &w) in hist.counts.iter() {
            elements.push(e.last());
            weights.push(w);
        }

        let weighted_index = WeightedIndex::new(&weights)
            .expect("Histogram cannot be empty");

        WeightedSampler { elements, weighted_index }
    }
}

// In the future, Flow and Obfuscator should implement this trait
// to allow streaming workloads and reduce memory pressure
pub trait PacketSource {
    fn next(&mut self) -> Option<Packet>;
}

#[derive(Debug)]
pub struct Generator<'a, R: rand::Rng> {
    model: &'a [HashMap<Sequence<PacketProjection>, WeightedSampler<PacketProjection>>],
    quantizer: &'a FlowQuantizer,
    markov_order: u32,
    history: Vec<Packet>,
    emitted: usize,
    length: usize,
    prev_timestamp: f64,
    rng: R
}

impl<'a, R: rand::Rng> Generator<'a, R> {
    pub fn new(
        model: &'a [HashMap<Sequence<PacketProjection>, WeightedSampler<PacketProjection>>],
        quantizer: &'a FlowQuantizer,
        markov_order: u32,
        length: usize,
        rng: R) -> Self
    {
        Self {
            model,
            quantizer,
            markov_order,
            history: Vec::with_capacity(markov_order as usize),
            emitted: 0,
            length,
            prev_timestamp: 0.0,
            rng
        }
    }
}

impl<'a, R: rand::Rng> PacketSource for Generator<'a, R> {
    fn next(&mut self) -> Option<Packet> {
        if self.emitted >= self.length { return None; }

        let quantizer = self.quantizer.quantizer_at(self.emitted);

        let quantized_history = Sequence::from(self.history
            .iter()
            .map(|packet| quantizer.quantize_packet(packet))
            .collect::<Vec<_>>());
        let quantized_packet = self.model[self.emitted]
            .get(&quantized_history)
            .unwrap()
            .sample(&mut self.rng);
        let mut packet = quantizer.dequantize(quantized_packet, &mut self.rng);

        // enforce timestamp monotonicity
        if packet.timestamp < self.prev_timestamp {
            packet.timestamp = self.prev_timestamp;
        }
        self.prev_timestamp = packet.timestamp;

        self.history.push(packet);
        if self.history.len() > self.markov_order as usize {
            self.history.remove(0);
        }
        self.emitted += 1;
        
        Some(packet)
    }
}

impl<'a, R: rand::Rng> Iterator for Generator<'a, R> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        PacketSource::next(self)
    }
}

pub fn generate_flow<R: rand::Rng>(
    samplers: &[HashMap<Sequence<PacketProjection>, WeightedSampler<PacketProjection>>],
    quantizer: &FlowQuantizer,
    markov_order: u32,
    flow_length: usize,
    flow_id: Vec<u8>,
    rng: R,
) -> Result<Flow, Box<dyn Error>> {
    if flow_length > samplers.len() {
        return Err(format!(
            "flow_length {} exceeds available packet-level distributions {}",
            flow_length,
            samplers.len()
        ).into());
    }

    let generator = Generator::new(samplers, quantizer, markov_order, flow_length, rng);
    let packets: Vec<Packet> = generator.collect();

    Ok(Flow {
        base: FlowMetadata {
            conn_id: flow_id,
            syn_ts: 0.0,
            synack_ts: 0.0,
            ack_ts: 0.0,
            len: packets.len(),
        },
        proto: ProtocolMetadata::Raw,
        packets,
    })
}

pub fn generate_flows<R: rand::Rng>(
    samplers: &[HashMap<Sequence<PacketProjection>, WeightedSampler<PacketProjection>>],
    quantizer: &FlowQuantizer,
    markov_order: u32,
    num_flows: usize,
    flow_length: usize,
    mut rng: R,
) -> Result<Vec<Flow>, Box<dyn Error>> {
    let mut flows = Vec::with_capacity(num_flows);

    for flow_index in 0..num_flows {
        flows.push(generate_flow(
            samplers,
            quantizer,
            markov_order,
            flow_length,
            format!("synthetic-flow-{flow_index:08}").into_bytes(),
            &mut rng,
        )?);
    }

    Ok(flows)
}

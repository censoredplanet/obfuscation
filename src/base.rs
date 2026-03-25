use std::fs::File;
use std::error::Error;
use hashbrown::HashMap;
use serde::{Serialize, Deserialize};
use rayon::prelude::*;
use flate2::read::GzDecoder;
use zstd::stream::read::Decoder;

use crate::merge::PostcardIO;
use crate::feature::{FeatureKind, EmitFeatures, FeatureEmitter};

#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub struct Packet {
    pub timestamp: f64,
    pub direction: f64,
    pub size: f64,
    pub entropy: f64
}

impl Packet {
    pub fn get_feature(&self, feature: &FeatureKind) -> f64 {
        match feature {
            FeatureKind::Timestamp => self.timestamp,
            FeatureKind::Direction => self.direction,
            FeatureKind::Size => self.size,
            FeatureKind::Entropy => self.entropy
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum TLSVersion {
    SSL,
    TLSv10,
    TLSv11,
    TLSv12,
    TLSv13,
    Unknown64282, // A Facebook-created variant of TLS 1.3
    Other // catch-all for now
}

impl From<&[u8]> for TLSVersion {
    fn from(bytes: &[u8]) -> Self {
        match bytes {
            b"SSL" => TLSVersion::SSL,
            b"TLSv10" => TLSVersion::TLSv10,
            b"TLSv11" => TLSVersion::TLSv11,
            b"TLSv12" => TLSVersion::TLSv12,
            b"TLSv13" => TLSVersion::TLSv13,
            b"unknown-64282" => TLSVersion::Unknown64282,
            _ => TLSVersion::Other,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FlowMetadata {
    pub conn_id: Vec<u8>,
    pub syn_ts:	f64,
    pub synack_ts: f64,
    pub ack_ts: f64,
    pub len: usize
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtocolMetadata {
    TLSMetadata {
        version: TLSVersion,
        client_hello: usize,
        server_hello: usize,
        ssl_est: usize
    },
    Raw
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Flow {
    pub base: FlowMetadata,
    pub proto: ProtocolMetadata,
    pub packets: Vec<Packet>
}

impl Flow {
    pub fn rtt_normalize(&mut self) {
        let client_to_observer = (self.base.ack_ts - self.base.synack_ts) / 2.0;
        let rtt = (self.base.synack_ts - self.base.syn_ts) + (2.0 * client_to_observer);

        let mut prev_ts: Option<f64> = None;
        for packet in self.packets.iter_mut() {
            let iat = match prev_ts {
                None => 0.0,
                Some(ts) => packet.timestamp - ts,
            };

            prev_ts = Some(packet.timestamp);

            packet.timestamp = iat / rtt;
        }
    }

    pub fn strip_tls_handshake(&mut self) {
        if let ProtocolMetadata::TLSMetadata { ssl_est, .. } = self.proto {
            self.packets.drain(0..=ssl_est as usize);
            self.proto = ProtocolMetadata::Raw;
            self.base.len = self.base.len - (ssl_est + 1);
        }
    }
}

impl EmitFeatures for Flow {
    type Value = f64;

    fn id(&self) -> &Vec<u8> {
        &self.base.conn_id
    }

    fn emit_features(&self, num_packets: usize, emitter: &mut dyn FeatureEmitter<f64>) {
        for packet in self.packets.iter().take(num_packets) {
            emitter.push_feature(packet.timestamp);
            emitter.push_feature(if packet.direction > 0.5 { packet.size } else { -packet.size });
        }
    }
}

impl PostcardIO for Vec<Flow> {}

#[derive(Debug, serde::Deserialize, Clone)]
#[serde(try_from = "String")]
pub enum FlowFilterPredicate {
    None,
    MinTLSDataPackets(usize),
    TLSVersionEq(TLSVersion),
    And(Box<FlowFilterPredicate>, Box<FlowFilterPredicate>)
}

impl FlowFilterPredicate {
    #[inline]
    pub fn matches(&self, flow: &Flow) -> bool {
        match self {
            FlowFilterPredicate::None => true,
            FlowFilterPredicate::MinTLSDataPackets(n) => {
                let tls_data_packets = match &flow.proto {
                    ProtocolMetadata::TLSMetadata { ssl_est, .. } => {
                        flow.base.len - (*ssl_est + 1)
                    }
                    ProtocolMetadata::Raw => return true,
                };

                tls_data_packets >= *n
            },
            FlowFilterPredicate::TLSVersionEq(tls_version) => {
                match &flow.proto {
                    ProtocolMetadata::Raw => false,
                    ProtocolMetadata::TLSMetadata { version, .. } => version == tls_version
                }
            },
            FlowFilterPredicate::And(left, right) => left.matches(flow) && right.matches(flow)
        }
    }
}

pub fn csv_reader(path: &str) -> Result<csv::Reader<Box<dyn std::io::Read>>, Box<dyn Error>> {
    let file = File::open(path)?;
    
    let reader: Box<dyn std::io::Read> = if path.ends_with(".gz") {
        Box::new(GzDecoder::new(file))
    } 
    else if path.ends_with(".zst") {
        Box::new(Decoder::new(file)?.single_frame())
    }
    else {
        Box::new(file)
    };
    
    Ok(csv::ReaderBuilder::new()
        .delimiter(b'\t')
        .quoting(false)
        .buffer_capacity(64 * 1024)
        .from_reader(reader))
}

// integers are faster to hash than strings
#[inline(always)]
pub fn to_key(id: &[u8]) -> u64 {
    u64::from_ne_bytes(id[..8].try_into().unwrap())
}

pub fn read_flows(flows_csv_path: &str, packets_csv_path: &str) -> Result<Vec<Flow>, Box<dyn Error>> {
    let mut flows_map: HashMap<u64, Flow> = HashMap::new();
    
    let mut flows_reader = csv_reader(flows_csv_path)?;
    let mut raw_record = csv::ByteRecord::new();

    flows_reader.byte_headers()?;
    while flows_reader.read_byte_record(&mut raw_record)? {
        let flow = unsafe {
            let flow_length = atoi::atoi(raw_record.get(8).unwrap()).unwrap();

            Flow {
                base: FlowMetadata {
                    conn_id: raw_record.get(0).unwrap().to_vec(),
                    syn_ts: str::from_utf8_unchecked(raw_record.get(1).unwrap()).parse::<f64>()?,
                    synack_ts: str::from_utf8_unchecked(raw_record.get(2).unwrap()).parse::<f64>()?,
                    ack_ts: str::from_utf8_unchecked(raw_record.get(3).unwrap()).parse::<f64>()?,
                    len: flow_length
                },
                proto: ProtocolMetadata::TLSMetadata {
                    version: raw_record.get(4).unwrap().into(),
                    client_hello: atoi::atoi(raw_record.get(5).unwrap()).unwrap(),
                    server_hello: atoi::atoi(raw_record.get(6).unwrap()).unwrap(),
                    ssl_est: atoi::atoi(raw_record.get(7).unwrap()).unwrap()
                },
                packets: Vec::with_capacity(flow_length)
            }
        };

        flows_map.insert(to_key(&flow.base.conn_id), flow);   
    }

    println!("Loaded connections!");

    let mut packets_reader = csv_reader(packets_csv_path)?;

    let mut curr_conn = None;
    let mut packets = Vec::with_capacity(50);
    
    packets_reader.byte_headers()?;
    while packets_reader.read_byte_record(&mut raw_record)? {
        let conn_id = to_key(&raw_record.get(0).unwrap());

        let packet = unsafe {
            Packet {
                timestamp: str::from_utf8_unchecked(raw_record.get(2).unwrap()).parse::<f64>()?,
                direction: str::from_utf8_unchecked(raw_record.get(3).unwrap()).parse::<f64>()?,
                size: str::from_utf8_unchecked(raw_record.get(4).unwrap()).parse::<f64>()?,
                entropy: str::from_utf8_unchecked(raw_record.get(5).unwrap()).parse::<f64>()?
            }
        };

        match curr_conn {
            Some(id) if id == conn_id => { packets.push(packet); }
            Some(id) => {
                // flush previous run
                if let Some(flow) = flows_map.get_mut(&id) {
                    flow.packets.append(&mut packets);
                }
                else {
                    packets.clear();
                }

                curr_conn = Some(conn_id);
                packets.push(packet);
            }
            None => {
                curr_conn = Some(conn_id);
                packets.push(packet);
            }
        }
    }

    if let Some(flow) = flows_map.get_mut(&curr_conn.unwrap()) {
        flow.packets.append(&mut packets);
    }

    // Quality check: ensure that the flow length matches the number of packets
    let flows = flows_map.into_par_iter()
                .filter(|(_, v)| v.base.len == v.packets.len())
                .map(|(_, v)| v)
                .collect::<Vec<_>>();
    
    println!("{}", flows.len());

    Ok(flows)
}

pub const MSS: usize = 1460;

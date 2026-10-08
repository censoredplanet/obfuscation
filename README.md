# Obfuscation

This repository contains components for collecting, modelling, and comparing proxy network traffic. It includes a Docker-based traffic generation testbed, a Rust command-line tool for turning captured traffic into statistical models, and open-source model artifacts generated from TLS traffic collected at an ISP network tap.

The intended workflow is:

1. Use the testbed to run proxy clients and servers, browse a domain list, and capture packet traces.
2. Convert the captured traffic into Zeek logs and then into CenKL flow files.
3. Use CenKL to build traffic models, compare models with KL divergence, inspect distributions, or generate synthetic flows.
4. Use the published models as baseline TLS model for calculating divergence.

The `cenkl/` and `testbed/` directories have their own READMEs with setup and usage details.

## CenKL

[`cenkl/`](cenkl/) contains the CenKL command-line tool. It parses Zeek logs, extracts per-packet flow features, builds statistical traffic models, computes KL divergence between models, and generates synthetic flows.

See [`cenkl/README.md`](cenkl/README.md) for build instructions, command usage, model formats, and the end-to-end analysis workflow.

## Models

[`models/`](models/) contains generated CenKL model artifacts that we are open-sourcing from TLS data collected at an ISP network tap. The artifacts are organized by feature set and Markov order, for example `size_direction/markov_order_0/` and `time/markov_order_1/`.

Each model directory contains:

- `model_assumptions.json`: the quantizer and Markov-order metadata used by CenKL
- `hist.bin`: the serialized TrafficProfile histogram model

## Testbed

[`testbed/`](testbed/) contains the Docker-based proxy testbed used to generate traffic captures. It includes client-server configurations for several proxy protocols, certificate setup, delay injection, packet capture scripts, and Playwright-based browsing harnesses.

See [`testbed/README.md`](testbed/README.md) for setup, protocol details, and experiment commands.
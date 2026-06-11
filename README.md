# Obfuscation

This repository contains components for collecting, modelling, and comparing proxy network traffic. It is organized as two self-contained projects: a Docker-based traffic generation testbed and a Rust command-line tool for turning captured traffic into statistical models.

The intended workflow is:

1. Use the testbed to run proxy clients and servers, browse a domain list, and capture packet traces.
2. Convert the captured traffic into Zeek logs and then into CensorKL flow files.
3. Use CensorKL to build traffic models, compare models with KL divergence, inspect distributions, or generate synthetic flows using already available traffic models.

## Repository layout

```text
.
├── README.md
├── censorkl/
└── testbed/
```

Each subdirectory has its own README with setup and usage details.

## CensorKL

[`censorkl/`](censorkl/) contains the CensorKL command-line tool. It parses Zeek logs, extracts per-packet flow features, builds statistical traffic models, and computes KL divergence between models, and generates synthetic flows.

See [`censorkl/README.md`](censorkl/README.md) for build instructions, command usage, model formats, and the end-to-end analysis workflow.

## Testbed

[`testbed/`](testbed/) contains the Docker-based proxy testbed used to generate traffic captures. It includes client-server configurations for several proxy protocols, certificate setup, delay injection, packet capture scripts, and Playwright-based browsing harnesses.

See [`testbed/README.md`](testbed/README.md) for setup, protocol details, and experiment commands.

## Where to start

Start with [`testbed/`](testbed/) if you need to produce new traffic captures. Start with [`censorkl/`](censorkl/) if you already have Zeek logs or flow files and want to build, inspect, compare, or sample from traffic models.

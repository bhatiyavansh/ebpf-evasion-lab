# Adaptive Evasion Analysis of eBPF-Based Runtime Security Systems

## Research Question

How does adaptive modification of containerized execution behavior affect the observability and detection capability of eBPF-based runtime security systems?

## Detectors

- Falco
- Tracee
- Tetragon

## Environment

- Kali Linux ARM64
- Linux 7.1.5+kali-arm64
- Docker
- Modern eBPF
- Linux BTF

## Experimental Method

Each behavior is evaluated using:

1. Baseline execution
2. Controlled adaptive modification
3. Detection observation
4. Event visibility assessment
5. Normalized result collection
6. Cross-tool comparison

## Metrics

- Detection
- Event visibility
- Detection latency
- Alert count
- Adaptive degradation

## Safety

Experiments use controlled, benign container behaviors. No destructive container escape exploitation is required.

## Status

Falco baseline and adaptive experiments are currently being established.

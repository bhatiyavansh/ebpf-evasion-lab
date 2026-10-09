#!/bin/bash

docker run --rm -it \
  --name falco \
  --privileged \
  -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /proc:/host/proc:ro \
  -v /etc:/host/etc:ro \
  -v "$HOME/ebpf-evasion-lab/detectors/falco/baseline_rules.yaml:/etc/falco/rules.d/baseline_rules.yaml:ro" \
  falcosecurity/falco:0.45.0

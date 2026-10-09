#!/bin/bash

docker run --rm -it \
  --name tetragon \
  --pid=host \
  --cgroupns=host \
  --privileged \
  -v /sys/kernel:/sys/kernel:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /var/run/docker/netns:/var/run/docker/netns:ro \
  -v "$HOME/ebpf-evasion-lab/detectors/tetragon/policies:/etc/tetragon/tetragon.tp.d:ro" \
  quay.io/cilium/tetragon:v1.6.0

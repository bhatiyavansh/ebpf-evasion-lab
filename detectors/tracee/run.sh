#!/bin/bash

docker run --rm -it \
  --name tracee \
  --pid=host \
  --cgroupns=host \
  --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /var/run:/var/run:ro \
  -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
  aquasec/tracee:latest \
  --events execve \
 --events openat \
 --events connect \
  --scope container \
  --output json

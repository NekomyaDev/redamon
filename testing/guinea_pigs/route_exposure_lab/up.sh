#!/usr/bin/env bash
# Start the lab on redamon-network, whatever /16 Docker gave it: the services
# take <prefix>.93-.96 of the network's own subnet.
set -euo pipefail
cd "$(dirname "$0")"
subnet=$(docker network inspect redamon-network --format '{{(index .IPAM.Config 0).Subnet}}')
export LAB_NET_PREFIX="$(echo "$subnet" | cut -d. -f1-3)"
echo "redamon-network $subnet -> lab on ${LAB_NET_PREFIX}.93-.96"
docker compose up -d --build "$@"

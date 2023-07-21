#!/bin/bash
# Author - Brennan Paciorek <bpaciore@redhat.com>
# Description - Benchmark firewalld downtime while reloading and while restarting
# by measuring how many packets are dropped while firewalld is restarting/reloading
set -euo pipefail

cleanup() {
  rm -f /tmp/ping0
  rm -f /tmp/ping2
  rm -f /tmp/ping1
  rm -f /tmp/Containerfile
  podman stop --all
  podman rm --all
  podman network rm podmanbr0 || :
}
trap "cleanup 1>/dev/null" EXIT

cat > /tmp/Containerfile << EOF
FROM quay.io/centos/centos:stream8
RUN dnf -y install systemd
RUN dnf -y install firewalld nc
EXPOSE 31337
CMD /usr/lib/systemd/systemd 
EOF

# Initial container setup #
{
  podman network create --subnet 172.16.1.0/24 --gateway 172.16.1.1 --interface-name podmanbr0 podmanbr0
  imageid=$(podman build -q /tmp)
  podman run -d --rm --rmi --privileged --net podmanbr0 --ip 172.16.1.2 --name test-firewalld "$imageid" /usr/lib/systemd/systemd
  sleep 5 # Wait reasonable amount of time for container to start services
  
  # Firewall rule setup #
  podman exec test-firewalld firewall-cmd --permanent --add-icmp-block "echo-request"
  # firewall-cmd reload waits for dbus response, systemctl will not
  podman exec test-firewalld firewall-cmd --reload
} > /dev/null 2>/dev/null

NUM_PINGS=50
TIMEOUT=2

# The following ping should have 100% packet loss
ping -c "$NUM_PINGS" -W "$TIMEOUT" -i 0.01 172.16.1.2 1>/tmp/ping0 || :

# Begin downtime comparision #
ping -c "$NUM_PINGS" -W "$TIMEOUT" -i 0.01 172.16.1.2 1>/tmp/ping1 || : &
pid="$!"
podman exec test-firewalld systemctl reload firewalld.service
wait "$pid"

ping -c "$NUM_PINGS" -W "$TIMEOUT" -i 0.01 172.16.1.2 1>/tmp/ping2 || : &
pid="$!"
podman exec test-firewalld systemctl restart firewalld.service
wait "$pid"

# Print Results
tail -2 /tmp/ping0 | head -1 | awk '{print $4}'
tail -2 /tmp/ping1 | head -1 | awk '{print $4}'
tail -2 /tmp/ping2 | head -1 | awk '{print $4}'


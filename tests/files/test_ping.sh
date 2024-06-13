#!/usr/bin/env bash
# Author - Brennan Paciorek <bpaciore@redhat.com>
# Description - Benchmark firewalld downtime while reloading and while restarting
# by measuring how many packets are dropped while firewalld is restarting/reloading
set -euo pipefail

TEST_DEBUG="${TEST_DEBUG:-false}"

if [ "$TEST_DEBUG" = true ]; then
  exec 6>&1
  set -x
else
  exec 6> /dev/null
fi

cleanup() {
  rm -f /tmp/ping0
  rm -f /tmp/ping2
  rm -f /tmp/ping1
  rm -f /tmp/Containerfile
  podman stop --all
  podman rm --all
}
trap "cleanup 1>&6 2>&6" EXIT

cat > /tmp/Containerfile << EOF
FROM quay.io/centos/centos:stream9
RUN dnf -y install systemd firewalld
CMD /usr/lib/systemd/systemd
EOF

# Initial container setup #
{
  imageid=$(podman build -q /tmp)
  podman run -d --rm --rmi --privileged --name test-firewalld "$imageid" /usr/lib/systemd/systemd
  ip=$(podman inspect -f "{{.NetworkSettings.IPAddress}}" test-firewalld)
  sleep 5 # Wait reasonable amount of time for container to start services
  # Firewall rule setup #
  podman exec test-firewalld firewall-cmd --permanent --add-icmp-block "echo-request"
  # firewall-cmd reload waits for dbus response, systemctl will not
  podman exec test-firewalld firewall-cmd --reload
} 1>&6 2>&6

NUM_PINGS=50
TIMEOUT=2

# The following ping should have 100% packet loss
ping -c "$NUM_PINGS" -W "$TIMEOUT" -i 0.01 "$ip" 1>/tmp/ping0 || :

# Begin downtime comparision #
ping -c "$NUM_PINGS" -W "$TIMEOUT" -i 0.01 "$ip" 1>/tmp/ping1 || : &
pid="$!"
podman exec test-firewalld systemctl reload firewalld.service
wait "$pid"

ping -c "$NUM_PINGS" -W "$TIMEOUT" -i 0.01 "$ip" 1>/tmp/ping2 || : &
pid="$!"
podman exec test-firewalld systemctl restart firewalld.service
wait "$pid"

# Print Results
tail -2 /tmp/ping0 | head -1 | awk '{print $4}'
tail -2 /tmp/ping1 | head -1 | awk '{print $4}'
tail -2 /tmp/ping2 | head -1 | awk '{print $4}'


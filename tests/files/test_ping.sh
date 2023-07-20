#!/bin/bash
# Author - Brennan Paciorek <bpaciore@redhat.com>
# Description - Benchmark firewalld downtime while reloading and while restarting
# by measuring how many packets are dropped while firewalld is restarting/reloading

cat > /tmp/Containerfile << EOF
FROM quay.io/centos/centos:stream8
RUN dnf -y install systemd
RUN dnf -y install firewalld nc
EXPOSE 31337
CMD /usr/lib/systemd/systemd 
EOF

trap "rm -f /tmp/Containerfile" EXIT

# Initial container setup #
{
  podman network create --subnet 172.16.1.0/24 --gateway 172.16.1.1 --interface-name podmanbr0 podmanbr0
  trap "podman network rm podmanbr0" EXIT
  imageid=$(podman build -q /tmp)
  podman run -d --privileged --net podmanbr0 --ip 172.16.1.2 --name test-firewalld --rm $imageid /usr/lib/systemd/systemd || exit 1
  trap "podman stop test-firewalld" EXIT
  sleep 5 # Wait reasonable amount of time for container to start services
  
  # Firewall rule setup #
  podman exec test-firewalld firewall-cmd --permanent --add-icmp-block "echo-request"
  # firewall-cmd reload waits for dbus response, systemctl will not
  podman exec test-firewalld firewall-cmd --reload
} > /dev/null 2>/dev/null
# The following ping should have 100% packet loss
ping -c 500 -i 0.01 172.16.1.2 1>/tmp/ping0 2>/dev/null
trap "rm -f /tmp/ping0" EXIT

# Begin downtime comparision #
ping -c 500 -i 0.01 172.16.1.2 1>/tmp/ping1 2>/dev/null &
pid=$!
trap "rm -f /tmp/ping1" EXIT
podman exec test-firewalld systemctl restart firewalld.service
wait $pid

ping -c 500 -i 0.01 172.16.1.2 1>/tmp/ping2 2>/dev/null &
pid=$!
trap "rm -f /tmp/ping2" EXIT
podman exec test-firewalld systemctl reload firewalld.service
wait $pid

# Print Results
cat /tmp/ping0 | tail -2 | head -1 | awk '{print $4}'
cat /tmp/ping1 | tail -2 | head -1 | awk '{print $4}'
cat /tmp/ping2 | tail -2 | head -1 | awk '{print $4}'


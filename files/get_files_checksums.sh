#!/bin/bash

set -euo pipefail

python_cmd="$1"
firewall_conf_root="${2:-/etc/firewalld}"
firewall_service="${3:-firewalld}"
remove="${4:-false}"

listfile=$(mktemp)
firewallconf=$(mktemp)
# shellcheck disable=SC2064
trap "rm -f $listfile $firewallconf" EXIT

find "$firewall_conf_root" -name \*.xml | while read -r file; do
    cksum=$(xmllint --c14n "$file" | sha256sum | awk '{print $1}')
    echo "$cksum" "$file"
done > "$listfile"

if [ -f "$firewall_conf_root/firewalld.conf" ]; then
    cp "$firewall_conf_root/firewalld.conf" "$firewallconf"
    "$python_cmd" -c 'import os, sys
from firewall.core.io.firewalld_conf import firewalld_conf
fc = firewalld_conf(sys.argv[1])
fc.read(); os.unlink(sys.argv[1])
fc.write()
' "$firewallconf"
    cksum=$(sha256sum "$firewallconf" | awk '{print $1}')
    echo "$cksum" "$firewall_conf_root/firewalld.conf" >> "$listfile"
fi

if [ "${remove:-false}" = true ]; then
    find "$firewall_conf_root" -name \*.xml -exec rm -f {} \;
    rm -f "$firewall_conf_root/firewalld.conf"
    if [ -s "$listfile" ] ; then
        systemctl restart "$firewall_service"
    fi
fi

cat "$listfile"

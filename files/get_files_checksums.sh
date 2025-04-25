#!/usr/bin/env bash

set -euo pipefail

python_cmd="$1"
firewall_conf_root="${2:-/etc/firewalld}"
remove="${3:-false}"
package="${4:-}"
firewall_usr_lib="${5:-}"
booted="${6:-}"

listfile=$(mktemp)
firewallconf=$(mktemp)
# shellcheck disable=SC2064
trap "rm -f $listfile $firewallconf" EXIT

find "$firewall_conf_root" -name \*.xml | while read -r file; do
    cksum=$(xmllint --c14n "$file" | sha256sum | awk '{print $1}')
    if [ -n "$firewall_usr_lib" ]; then
        usr_lib_file="${firewall_usr_lib}${file##"$firewall_conf_root"}"
        if [ -f "$usr_lib_file" ]; then
            cksum_usr_lib=$(xmllint --c14n "$usr_lib_file" | sha256sum | awk '{print $1}')
            if [ "$cksum" != "$cksum_usr_lib" ]; then
                echo "$cksum" "$file"
            fi
        else
            echo "$cksum" "$file"
        fi
    else
        echo "$cksum" "$file"
    fi
done > "$listfile"

set +o pipefail

orig_conf="$firewall_conf_root/firewalld.conf"
remove_firewall_conf=true
if [ -f "$orig_conf" ]; then
    if [ -z "$package" ] || rpm -V "$package" | grep -q "c ${orig_conf}$"; then
        cp "$orig_conf" "$firewallconf"
        "$python_cmd" -c 'import os, sys
from firewall.core.io.firewalld_conf import firewalld_conf
fc = firewalld_conf(sys.argv[1])
fc.read(); os.unlink(sys.argv[1])
fc.write()
' "$firewallconf"
        cksum=$(sha256sum "$firewallconf" | awk '{print $1}')
        echo "$cksum" "$orig_conf" >> "$listfile"
    else
        remove_firewall_conf=false
    fi
fi

set -o pipefail

if [ "${remove:-false}" = true ]; then
    find "$firewall_conf_root" -name \*.xml -exec rm -f {} \;
    if [ "$remove_firewall_conf" = true ]; then
	"$python_cmd" -c 'import sys
from firewall.core.io.firewalld_conf import firewalld_conf
fc = firewalld_conf(None) # open(None, "r") throws an Exception in fc.read()
try:
    fc.read() # should populate fallback configuration
except Exception:
    pass
fc.filename=sys.argv[1] # Change target firewalld.conf write target
fc.write() # update firewalld.conf
' "$orig_conf" 2>/dev/null
    fi
    if [ -s "$listfile" ] && [ -n "$booted" ] ; then
        firewall-cmd --reload > /dev/null
    fi
fi

cat "$listfile"

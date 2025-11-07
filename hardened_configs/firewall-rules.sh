#!/bin/bash
# CockLocker - Firewall rules for hardened Cockpit
# Defense-in-depth network security

set -euo pipefail

# Allow only specific IPs/networks
ALLOWED_NETWORKS=(
    "127.0.0.1/32"
    "::1/128"
    # Add your trusted networks here
    # "192.168.1.0/24"
)

COCKPIT_PORT="9090"

echo "[*] Applying CockLocker firewall rules..."

# Flush existing rules for Cockpit port
iptables -D INPUT -p tcp --dport "$COCKPIT_PORT" -j ACCEPT 2>/dev/null || true
ip6tables -D INPUT -p tcp --dport "$COCKPIT_PORT" -j ACCEPT 2>/dev/null || true

# Default deny for Cockpit port
iptables -A INPUT -p tcp --dport "$COCKPIT_PORT" -j DROP
ip6tables -A INPUT -p tcp --dport "$COCKPIT_PORT" -j DROP

# Allow from trusted networks only
for network in "${ALLOWED_NETWORKS[@]}"; do
    if [[ "$network" =~ : ]]; then
        # IPv6
        ip6tables -I INPUT -p tcp --dport "$COCKPIT_PORT" -s "$network" -j ACCEPT
        echo "[+] Allowed IPv6 network: $network"
    else
        # IPv4
        iptables -I INPUT -p tcp --dport "$COCKPIT_PORT" -s "$network" -j ACCEPT
        echo "[+] Allowed IPv4 network: $network"
    fi
done

# Rate limiting to prevent brute force
iptables -I INPUT -p tcp --dport "$COCKPIT_PORT" -m state --state NEW -m recent --set
iptables -I INPUT -p tcp --dport "$COCKPIT_PORT" -m state --state NEW -m recent --update --seconds 60 --hitcount 10 -j DROP

ip6tables -I INPUT -p tcp --dport "$COCKPIT_PORT" -m state --state NEW -m recent --set
ip6tables -I INPUT -p tcp --dport "$COCKPIT_PORT" -m state --state NEW -m recent --update --seconds 60 --hitcount 10 -j DROP

echo "[+] Rate limiting enabled (max 10 connections per minute)"

# Log dropped connections
iptables -A INPUT -p tcp --dport "$COCKPIT_PORT" -j LOG --log-prefix "CockLocker-DROP: " --log-level 4
ip6tables -A INPUT -p tcp --dport "$COCKPIT_PORT" -j LOG --log-prefix "CockLocker-DROP: " --log-level 4

echo "[+] CockLocker firewall rules applied successfully"

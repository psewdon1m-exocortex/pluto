#!/bin/sh
set -eu
mkdir -p /home/vault/gateway
chown 1001:1001 /home/vault/gateway
cp /hostkeys/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key
chmod 0600 /etc/ssh/ssh_host_ed25519_key
exec /entrypoint

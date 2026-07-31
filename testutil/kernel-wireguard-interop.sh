#!/usr/bin/env bash
set -euo pipefail

binary=${1:?usage: kernel-wireguard-interop.sh PATH_TO_TUNSTILE}
binary=$(realpath "$binary")
work_dir=$(mktemp -d)
umask 077
peer_namespace=tunstile-ci-peer
host_link=ts-ci-host
peer_link=ts-ci-peer
wireguard_interface=wg-ci
tunstile_pid=

cleanup() {
  set +e
  if [[ -n "$tunstile_pid" ]]; then
    sudo kill "$tunstile_pid" 2>/dev/null
    wait "$tunstile_pid" 2>/dev/null
  fi
  sudo ip netns delete "$peer_namespace" 2>/dev/null
  sudo ip link delete "$host_link" 2>/dev/null
}
trap cleanup EXIT

wg genkey > "$work_dir/tunstile.key"
wg pubkey < "$work_dir/tunstile.key" > "$work_dir/tunstile.pub"
wg genkey > "$work_dir/peer.key"
wg pubkey < "$work_dir/peer.key" > "$work_dir/peer.pub"
chmod 600 "$work_dir/tunstile.key" "$work_dir/peer.key"

tunstile_private_key=$(<"$work_dir/tunstile.key")
tunstile_public_key=$(<"$work_dir/tunstile.pub")
peer_public_key=$(<"$work_dir/peer.pub")

cat > "$work_dir/tunstile.conf" <<EOF
[Interface]
PrivateKey = $tunstile_private_key
Address = 10.200.0.1/32
ListenPort = 51820
MTU = 1420

[Peer]
PublicKey = $peer_public_key
Endpoint = 192.0.2.2:51821
AllowedIPs = 10.200.0.2/32
PersistentKeepalive = 1
EOF

sudo ip netns add "$peer_namespace"
sudo ip link add "$host_link" type veth peer name "$peer_link"
sudo ip address add 192.0.2.1/24 dev "$host_link"
sudo ip link set "$host_link" up
sudo ip link set "$peer_link" netns "$peer_namespace"
sudo ip netns exec "$peer_namespace" ip link set lo up
sudo ip netns exec "$peer_namespace" ip address add 192.0.2.2/24 dev "$peer_link"
sudo ip netns exec "$peer_namespace" ip link set "$peer_link" up

sudo ip netns exec "$peer_namespace" ip link add "$wireguard_interface" type wireguard
sudo ip netns exec "$peer_namespace" wg set "$wireguard_interface" \
  private-key "$work_dir/peer.key" \
  listen-port 51821 \
  peer "$tunstile_public_key" \
  endpoint 192.0.2.1:51820 \
  allowed-ips 10.200.0.1/32 \
  persistent-keepalive 1
sudo ip netns exec "$peer_namespace" ip address add 10.200.0.2/32 dev "$wireguard_interface"
sudo ip netns exec "$peer_namespace" ip link set "$wireguard_interface" up
sudo ip netns exec "$peer_namespace" ip route add 10.200.0.1/32 dev "$wireguard_interface"

sudo "$binary" "$work_dir/tunstile.conf" > "$work_dir/tunstile.log" 2>&1 &
tunstile_pid=$!

tun_interface=
for _ in $(seq 1 100); do
  tun_interface=$(ip -o -4 address show | awk '$4 == "10.200.0.1/32" { print $2; exit }')
  if [[ -n "$tun_interface" ]]; then
    break
  fi
  if ! sudo kill -0 "$tunstile_pid" 2>/dev/null; then
    cat "$work_dir/tunstile.log"
    exit 1
  fi
  sleep 0.1
done

if [[ -z "$tun_interface" ]]; then
  echo "tunstile did not create its TUN interface" >&2
  cat "$work_dir/tunstile.log"
  exit 1
fi

sudo ip route replace 10.200.0.2/32 dev "$tun_interface"
if ! sudo ip netns exec "$peer_namespace" ping -c 3 -W 5 10.200.0.1; then
  sudo ip netns exec "$peer_namespace" wg show "$wireguard_interface"
  cat "$work_dir/tunstile.log"
  exit 1
fi

latest_handshake=$(sudo ip netns exec "$peer_namespace" \
  wg show "$wireguard_interface" latest-handshakes | awk '{ print $2 }')
if [[ -z "$latest_handshake" || "$latest_handshake" == 0 ]]; then
  echo "kernel WireGuard peer did not record a handshake" >&2
  sudo ip netns exec "$peer_namespace" wg show "$wireguard_interface"
  cat "$work_dir/tunstile.log"
  exit 1
fi

sudo ip netns exec "$peer_namespace" wg show "$wireguard_interface"
cat "$work_dir/tunstile.log"

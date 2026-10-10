#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
# udpcheck-node: installer of a node for the UDP check network (Linux with systemd, OpenWrt). Source: https://dagart.xyz/en/
#
#   Install (one line for any Linux and OpenWrt router; it picks curl or wget and sudo itself):
#     (curl -fsSL https://dagart.xyz/en/i 2>/dev/null || wget -qO- https://dagart.xyz/en/i) | sh
#   Remove:
#     (curl -fsSL https://dagart.xyz/en/i 2>/dev/null || wget -qO- https://dagart.xyz/en/i) | sh -s -- uninstall
#
# What it does: installs Python 3 (if missing), downloads the agent, verifies its SHA-256 and signature, creates the udpcheck-node service
# that runs as a temporary unprivileged user (systemd DynamicUser). The agent only makes outgoing connections: to the hub over HTTPS
# and to the project's servers over UDP/TCP. No domain or certificate is needed.
# The role is picked automatically: a machine with a public IPv4 (VPS, server) -> ANCHOR SERVER: answers other nodes' checks on the hub's assignments
# (open UDP 47321, 47322 and TCP 47321; the hub checks reachability itself). Home PC, router, machine behind NAT -> NODE: checks your own network.
# Another role: UDPCHECK_ROLE=node|ref|both before sh:  ... | UDPCHECK_ROLE=node sh
# The installer does not touch the firewall, SSH or other services: you open the ports for the anchor role yourself.
set -eu

HUB="${UDPCHECK_HUB:-https://dagart.xyz}"
ROLE="${UDPCHECK_ROLE:-auto}"   # auto | node (checks its own network) | ref (anchor server) | both
if [ "${UDPCHECK_REF:-}" = 0 ] && [ "$ROLE" = auto ]; then ROLE=node; fi      # old variable: REF=0 meant "node only"
AGENT_SHA256="a3192fea3a83c971f370a0c7d448f5d41b78da88ac18952a96452db1d5613f30"
DIR=/opt/udpcheck-node
STATE=/var/lib/udpcheck-node
SVC=udpcheck-node
UNIT="/etc/systemd/system/${SVC}.service"

say() { printf '%s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time "${3:-60}" "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T "${3:-60}" -O "$2" "$1"
  else
    return 1
  fi
}

RELEASE_PUB='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAhNm81cJlzBt8A5K+e6Lhxb47/+Q/WCObOgWJwCpYDYY=
-----END PUBLIC KEY-----'

verify_sig() {
  if ! command -v openssl >/dev/null 2>&1 || ! openssl pkeyutl -help 2>&1 | grep -q rawin; then
    say "The agent signature was not verified (no openssl with Ed25519): only the checksum was verified."
    return 0
  fi
  VP="$(mktemp)"; VS="$(mktemp)"
  printf '%s\n' "$RELEASE_PUB" > "$VP"
  ${2:-fetch} "$HUB/node/udpcheck_node.py.sig" "$VS" 30 || { rm -f "$VP" "$VS"; die "the hub has no agent signature. Installation aborted."; }
  if openssl pkeyutl -verify -pubin -inkey "$VP" -rawin -in "$1" -sigfile "$VS" >/dev/null 2>&1; then
    rm -f "$VP" "$VS"; say "Agent signature verified."
  else
    rm -f "$VP" "$VS"; die "the agent signature does not match the release key. Installation aborted."
  fi
}

[ "$(uname -s)" = Linux ] || die "the installer works on Linux only (on macOS and Windows run the agent manually: download $HUB/node/udpcheck_node.py and run python3 udpcheck_node.py)"

if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    say "Root rights are needed: restarting the installer through sudo..."
    SELF="$(mktemp)"
    fetch "$HUB/install-node.en.sh" "$SELF" 30 || die "could not download the installer again"
    exec sudo env UDPCHECK_YES="${UDPCHECK_YES:-0}" UDPCHECK_HUB="$HUB" UDPCHECK_ROLE="$ROLE" UDPCHECK_OPEN_FW="${UDPCHECK_OPEN_FW:-}" sh -c 'f="$1"; shift; sh "$f" "$@"; r=$?; rm -f "$f"; exit $r' _ "$SELF" "$@"
  fi
  die "root rights are needed and sudo was not found. Log in as root (su -) and repeat the same command."
fi

ACTION="${1:-install}"

OPENWRT=0
if [ -f /etc/openwrt_release ] && [ -x /sbin/procd ]; then OPENWRT=1; fi

ROLE_WHY="role set manually"

detect_role() {
  case "$ROLE" in node|ref|both) return 0 ;; auto) ;; *) die "unknown role '$ROLE' (allowed: auto, node, ref, both)" ;; esac
  ROLE=node
  ROLE_WHY="home network, router or a machine behind NAT"
  [ "$OPENWRT" = 1 ] && return 0
  DT="$(mktemp)"
  if fetch "$HUB/api/v2/ip" "$DT" 15 2>/dev/null; then
    PUB="$(sed -n 's/.*"ip": *"\([0-9.]*\)".*/\1/p' "$DT" | head -n1)"
    LOC="$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1; hostname -I 2>/dev/null | tr ' ' '\n')"
    if [ -n "$PUB" ] && printf '%s\n' "$LOC" | grep -qx "$PUB"; then
      ROLE=ref
      ROLE_WHY="the machine has a public IPv4, it is a server"
    fi
  fi
  rm -f "$DT"
}

FW_PORTS_UDP="47321 47322"
FW_PORTS_TCP="47321"

detect_fw() {
  FW=""
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -n1 | grep -qx 'Status: active'; then FW=ufw
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qi running; then FW=firewalld
  elif command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)|-j (DROP|REJECT)'; then FW=iptables
  elif command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q 'policy drop'; then FW=nft
  fi
}

fw_cmds() {
  case "$FW" in
    ufw)
      for p in $FW_PORTS_UDP; do echo "ufw allow $p/udp"; done
      for p in $FW_PORTS_TCP; do echo "ufw allow $p/tcp"; done ;;
    firewalld)
      echo "firewall-cmd --permanent $(for p in $FW_PORTS_UDP; do printf -- '--add-port=%s/udp ' "$p"; done)$(for p in $FW_PORTS_TCP; do printf -- '--add-port=%s/tcp ' "$p"; done)"
      echo "firewall-cmd --reload" ;;
    iptables)
      for p in $FW_PORTS_UDP; do echo "iptables -I INPUT -p udp --dport $p -j ACCEPT"; done
      for p in $FW_PORTS_TCP; do echo "iptables -I INPUT -p tcp --dport $p -j ACCEPT"; done ;;
    nft)
      echo "nft insert rule inet filter input udp dport { 47321, 47322 } accept   # your table and chain names may differ"
      echo "nft insert rule inet filter input tcp dport 47321 accept" ;;
  esac
}

fw_help() {
  say ""
  say "The hub could not reach the anchor server's ports from outside (UDP 47321, 47322 and TCP 47321 are needed)."
  if command -v ss >/dev/null 2>&1; then
    LISTEN="$(ss -uln 2>/dev/null | awk 'NR>1{print $4}' | tr '\n' ' ')"
    for p in $FW_PORTS_UDP; do
      case " $LISTEN" in
        *":$p "*) ;;
        *) say "  UDP $p: nothing listens on it on this machine (taken by another program?). Check: ss -ulnp | grep $p" ;;
      esac
    done
  fi
  detect_fw
  if [ -z "$FW" ]; then
    say "  No enabled firewall is visible on the machine itself (ufw, firewalld, iptables, nftables)."
    say "  So the ports are closed from outside: in the hosting panel (firewall or security groups) or behind NAT. Open UDP 47321, 47322 and TCP 47321 there,"
    say "  then: systemctl restart $SVC"
    return 0
  fi
  say "  Firewall found: $FW. Not open, judging by the hub's check: UDP 47321, UDP 47322, TCP 47321."
  say "  To open them, run:"
  fw_cmds | while read -r c; do say "    $c"; done
  ANS=n
  if [ "${UDPCHECK_OPEN_FW:-}" = 1 ]; then ANS=y
  elif [ "${UDPCHECK_OPEN_FW:-}" = 0 ] || [ "${UDPCHECK_YES:-0}" = 1 ] || [ ! -r /dev/tty ]; then ANS=n
  else
    printf '  Run these commands now? [y/N] '
    read -r ANS < /dev/tty || ANS=n
  fi
  case "$ANS" in
    y|Y) ;;
    *) say "  Changing nothing. Run the commands yourself, then: systemctl restart $SVC"; return 0 ;;
  esac
  if [ "$FW" = nft ]; then
    say "  I do not open ports for nftables myself: table names differ everywhere, substitute yours into the commands above and run them manually."
    return 0
  fi
  fw_cmds | while read -r c; do
    say "  running: $c"
    sh -c "$c" >/dev/null 2>&1 || say "  failed: $c"
  done
  [ "$FW" = iptables ] && say "  iptables rules do not survive a reboot, save them (netfilter-persistent save or iptables-save)."
  TS="$(date '+%Y-%m-%d %H:%M:%S')"
  systemctl restart "$SVC"
  i=0; RL2=""
  while [ "$i" -lt 25 ] && [ -z "$RL2" ]; do
    sleep 1
    RL2="$(journalctl -u "$SVC" --no-pager -o cat --since "$TS" 2>/dev/null | grep 'Anchor role' | tail -1 || true)"
    i=$((i + 1))
  done
  if [ -n "$RL2" ]; then say "  $RL2"; else say "  I do not see the result of the check yet: journalctl -u $SVC -n 20"; fi
  return 0
}

say_role_notice() {
  case "$ROLE" in
    node)
      say "Role: NODE ($ROLE_WHY)."
      say "  Every ~15 minutes the agent gets a task from the hub, sends UDP to the anchor servers and reports the counters."
      say "  The hub sees your IP for the duration of the request and identifies the provider by ASN. The IP is not written to the database and is not given to anyone. No ports need to be opened." ;;
    ref)
      say "Role: ANCHOR SERVER ($ROLE_WHY)."
      say "  The machine will answer other nodes' checks on the hub's assignments and checks nothing itself."
      say "  Its IP will be known to the hub, the network's nodes and the browsers of site visitors it helps check (like any STUN server);"
      say "  the server will see their IPs. Traces to visitors are not passed to it."
      say "  Open UDP 47321, 47322 and TCP 47321 in the firewall (the installer does not change the firewall itself; if the ports turn out to be closed, it will offer to open them and ask for your consent), otherwise the server stays inactive." ;;
    both)
      say "Role: NODE AND ANCHOR SERVER ($ROLE_WHY)."
      say "  The agent checks your network and also answers other nodes' checks. The IP will be known to the hub and to the nodes the hub assigns this server to."
      say "  Open UDP 47321, 47322 and TCP 47321 in the firewall (the installer does not change the firewall itself; if the ports turn out to be closed, it will offer to open them and ask for your consent)." ;;
  esac
  say "  Another role: UDPCHECK_ROLE=node, ref or both before sh."
}

pyfetch() {
  python3 -c 'import sys,urllib.request; open(sys.argv[2],"wb").write(urllib.request.urlopen(sys.argv[1], timeout=int(sys.argv[3])).read())' "$1" "$2" "${3:-60}"
}

openwrt_install() {
  say "udpcheck-node: connecting this router to the UDP check network (OpenWrt)"
  say ""
  say "What will be done:"
  say "  1. Python 3 and the needed modules will be installed through the OpenWrt package manager (apk or opkg), about 30 MB of flash;"
  say "  2. the agent is downloaded from $HUB/node/udpcheck_node.py and its SHA-256 checksum is verified;"
  say "  3. the udpcheck-node service (procd) is created: it runs as user nobody, outgoing connections only."
  detect_role
  say_role_notice
  say ""
  FREE="$(df -k /overlay 2>/dev/null | awk 'NR==2{print $4}')"
  [ -n "$FREE" ] || FREE="$(df -k / | awk 'NR==2{print $4}')"
  if [ "$FREE" -lt 40000 ] 2>/dev/null; then
    die "not enough space: about $((FREE / 1024)) MB free, at least 40 MB needed. Free up space or attach a USB drive (extroot)."
  fi
  if [ "${UDPCHECK_YES:-0}" != 1 ]; then
    say "Starting in 5 seconds. Cancel: Ctrl+C."
    sleep 5
  fi
  say "Updating the package list and installing Python (this may take a few minutes)..."
  PYPKGS="python3-light python3-urllib python3-openssl python3-codecs ca-bundle"
  if command -v apk >/dev/null 2>&1; then
    apk update >/dev/null 2>&1 || die "apk update failed: check the internet and the time on the router"
    apk add $PYPKGS >/dev/null 2>&1 || die "could not install the Python packages through apk"
  elif command -v opkg >/dev/null 2>&1; then
    opkg update >/dev/null 2>&1 || die "opkg update failed: check the internet and the time on the router"
    opkg install $PYPKGS >/dev/null 2>&1 || die "could not install the Python packages through opkg"
  else
    die "no package manager found (apk or opkg)"
  fi
  command -v python3 >/dev/null 2>&1 || die "python3 was not found after installation"
  say "Checking that the hub is reachable..."
  pyfetch "$HUB/api/v2/stats?hours=1" /dev/null 20 || die "the hub $HUB is unreachable from the router (outgoing HTTPS and the correct time on the router are needed)"
  TMP="$(mktemp)"
  trap 'rm -f "$TMP"' EXIT
  say "Downloading the agent..."
  pyfetch "$HUB/node/udpcheck_node.py" "$TMP" 60 || die "could not download the agent"
  GOT="$(sha256sum "$TMP" | cut -d' ' -f1)"
  [ "$GOT" = "$AGENT_SHA256" ] || die "the agent checksum does not match (got $GOT, expected $AGENT_SHA256). Installation aborted."
  verify_sig "$TMP" pyfetch
  python3 -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "$TMP" || die "the downloaded file is not valid Python"
  mkdir -p /opt/udpcheck-node /etc/udpcheck-node
  cp "$TMP" /opt/udpcheck-node/udpcheck_node.py
  chmod 644 /opt/udpcheck-node/udpcheck_node.py
  chmod 755 /opt/udpcheck-node
  chown nobody /etc/udpcheck-node 2>/dev/null || true
  chmod 700 /etc/udpcheck-node
  cat > /etc/init.d/udpcheck-node <<'INITEOF'
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1

start_service() {
	procd_open_instance
	procd_set_param command /usr/bin/python3 /opt/udpcheck-node/udpcheck_node.py --config /etc/udpcheck-node/config.json
	procd_set_param user nobody
	procd_set_param env UDPCHECK_LANG=en
	procd_set_param no_new_privs 1
	procd_set_param respawn 3600 20 0
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}
INITEOF
  chmod 755 /etc/init.d/udpcheck-node
  if [ "$ROLE" != node ]; then sed -i "s|udpcheck_node.py --config|udpcheck_node.py --role $ROLE --config|" /etc/init.d/udpcheck-node; fi
  /etc/init.d/udpcheck-node enable
  /etc/init.d/udpcheck-node restart
  say "Service started, waiting for the node to register..."
  i=0
  CALL=""
  while [ "$i" -lt 25 ]; do
    CALL="$(logread 2>/dev/null | grep 'Callsign' | tail -1 || true)"
    [ -n "$CALL" ] && break
    i=$((i + 1))
    sleep 1
  done
  say ""
  if [ -n "$CALL" ]; then say "Done. $CALL"; else say "The service started, but I do not see the registration in the log yet. Check: logread | grep udpcheck"; fi
  if [ "$ROLE" != node ]; then
    i=0; RL=""
    while [ "$i" -lt 20 ] && [ -z "$RL" ]; do RL="$(logread 2>/dev/null | grep 'Anchor role' | tail -1 || true)"; [ -n "$RL" ] || sleep 1; i=$((i + 1)); done
    if [ -n "$RL" ]; then say "$RL"; fi
  fi
  say ""
  say "Status:     /etc/init.d/udpcheck-node status"
  say "Log:        logread -f | grep -i udpcheck"
  say "Results:    $HUB/en/ (the check button and the provider table)"
  say "Remove:     (curl -fsSL $HUB/en/i 2>/dev/null || wget -qO- $HUB/en/i) | sh -s -- uninstall"
}

if [ "$ACTION" = uninstall ] && [ "$OPENWRT" = 1 ]; then
  say "Removing the udpcheck node (OpenWrt)..."
  /etc/init.d/udpcheck-node stop >/dev/null 2>&1 || true
  /etc/init.d/udpcheck-node disable >/dev/null 2>&1 || true
  rm -f /etc/init.d/udpcheck-node
  rm -rf /opt/udpcheck-node /etc/udpcheck-node
  say "Done: the service, files and settings (including the node token) are removed. The Python packages stay: remove them with apk del python3-light (OpenWrt 25.12+) or opkg remove python3-light."
  exit 0
fi

if [ "$ACTION" = uninstall ]; then
  say "Removing the udpcheck node..."
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$SVC" >/dev/null 2>&1 || true
  fi
  rm -f "$UNIT"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  rm -rf "$DIR" "$STATE" /var/lib/private/udpcheck-node
  say "Done: the service, files and settings (including the node token) are removed."
  exit 0
fi
[ "$ACTION" = install ] || die "unknown action '$ACTION' (allowed: install, uninstall)"

if [ "$OPENWRT" = 1 ]; then
  openwrt_install
  exit 0
fi

if [ ! -d /run/systemd/system ]; then
  if command -v curl >/dev/null 2>&1; then DL="curl -fsSL $HUB/node/udpcheck_node.py -o udpcheck_node.py"; else DL="wget -qO udpcheck_node.py $HUB/node/udpcheck_node.py"; fi
  PYHINT=""
  command -v python3 >/dev/null 2>&1 || { command -v apk >/dev/null 2>&1 && PYHINT="first install Python: apk add python3; "; }
  die "systemd not found. The installer supports only systems with systemd for now. Manual run: ${PYHINT}${DL} && python3 udpcheck_node.py"
fi
command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || die "curl or wget is needed"

say "udpcheck-node: connecting this server to the UDP check network"
say ""
say "What will be done:"
say "  1. python3 (3.7 or newer) is installed if needed;"
say "  2. the agent is downloaded from $HUB/node/udpcheck_node.py, its SHA-256 checksum is verified, the file is put into $DIR;"
say "  3. the $SVC service is created: a temporary unprivileged user, outgoing connections only."
detect_role
say_role_notice
say ""
if [ "${UDPCHECK_YES:-0}" != 1 ]; then
  say "Starting in 5 seconds. Cancel: Ctrl+C."
  sleep 5
fi

py_ok() { command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)' 2>/dev/null; }

if ! py_ok; then
  say "Python 3.7+ not found, trying to install it..."
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q python3 ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q python3 ca-certificates
  elif command -v zypper >/dev/null 2>&1; then
    zypper -n install python3 ca-certificates
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --noconfirm --needed python ca-certificates
  else
    die "could not detect the package manager: install Python 3.7+ manually and repeat"
  fi
  py_ok || die "Python 3.7+ is still not found after installation"
fi

say "Checking that the hub is reachable..."
fetch "$HUB/api/v2/stats?hours=1" /dev/null 20 || die "the hub $HUB is unreachable from this server (outgoing HTTPS is needed)"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
say "Downloading the agent..."
fetch "$HUB/node/udpcheck_node.py" "$TMP" 60 || die "could not download the agent"
if command -v sha256sum >/dev/null 2>&1; then
  GOT="$(sha256sum "$TMP" | cut -d' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
  GOT="$(shasum -a 256 "$TMP" | cut -d' ' -f1)"
else
  die "no sha256sum, nothing to verify the checksum with"
fi
[ "$GOT" = "$AGENT_SHA256" ] || die "the agent checksum does not match (got $GOT, expected $AGENT_SHA256). Installation aborted."
verify_sig "$TMP"
python3 -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "$TMP" || die "the downloaded file is not valid Python"

install -d -m 755 "$DIR"
install -m 644 "$TMP" "$DIR/udpcheck_node.py"

cat > "$UNIT" <<'UNITEOF'
[Unit]
Description=udpcheck: UDP check network node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/env python3 /opt/udpcheck-node/udpcheck_node.py --config /var/lib/udpcheck-node/config.json
Environment=UDPCHECK_LANG=en
DynamicUser=yes
StateDirectory=udpcheck-node
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
MemoryMax=96M
TasksMax=16
Restart=always
RestartSec=20

[Install]
WantedBy=multi-user.target
UNITEOF
chmod 644 "$UNIT"
if [ "$ROLE" != node ]; then
  sed -i -e "s|udpcheck_node.py --config|udpcheck_node.py --role $ROLE --config|" -e 's|^TasksMax=16|TasksMax=40|' "$UNIT"
fi

systemctl daemon-reload
systemctl enable "$SVC" >/dev/null 2>&1
systemctl restart "$SVC"

say "Service started, waiting for the node to register..."
i=0
CALL=""
while [ "$i" -lt 25 ]; do
  CALL="$(journalctl -u "$SVC" --no-pager -o cat --since '-3min' 2>/dev/null | grep -m1 'Callsign' || true)"
  [ -n "$CALL" ] && break
  i=$((i + 1))
  sleep 1
done

say ""
if [ -n "$CALL" ]; then
  say "Done. $CALL"
else
  say "The service started, but I do not see the registration in the log yet. Check: journalctl -u $SVC -n 30"
fi
if [ "$ROLE" != node ]; then
  i=0; RL=""
  while [ "$i" -lt 20 ] && [ -z "$RL" ]; do
    RL="$(journalctl -u "$SVC" --no-pager -o cat --since '-3min' 2>/dev/null | grep 'Anchor role' | tail -1 || true)"
    [ -n "$RL" ] || sleep 1
    i=$((i + 1))
  done
  if [ -n "$RL" ]; then say "$RL"; fi
  case "$RL" in *"not active"*) fw_help ;; esac
fi
say ""
say "Status:     systemctl status $SVC"
say "Log:        journalctl -u $SVC -f"
say "Results:    $HUB/en/ (the check button and the provider table)"
say "Remove:     (curl -fsSL $HUB/en/i 2>/dev/null || wget -qO- $HUB/en/i) | sh -s -- uninstall"

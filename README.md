# eap_proxy

Proxy EAP packets between interfaces on a  Ubiquiti Networks EdgeRouter™ Lite

Inspired by 1x_prox as posted here:

<http://www.dslreports.com/forum/r30693618->

AT&T Residential Gateway Bypass - True bridge mode!

## Instructions

- Copy `eap_proxy.sh` to `/config/scripts/post-config.d/eap_proxy.sh`
- Copy `eap_proxy.py` to `/config/scripts/eap_proxy.py`
- Adjust the settings in `eap_proxy.sh` as appropriate per the usage instructions below.

## EdgeRouter Sample Configuration

Here's an excerpt of my EdgeRouter configuration:

```
set interfaces ethernet eth0 description WAN
set interfaces ethernet eth0 duplex auto
set interfaces ethernet eth0 firewall in name WAN_IN
set interfaces ethernet eth0 firewall local name WAN_LOCAL
set interfaces ethernet eth0 speed auto
set interfaces ethernet eth0 vif 0 address dhcp
set interfaces ethernet eth0 vif 0 description 'WAN VLAN 0'
set interfaces ethernet eth0 vif 0 dhcp-options default-route update
set interfaces ethernet eth0 vif 0 dhcp-options default-route-distance 210
set interfaces ethernet eth0 vif 0 dhcp-options name-server update
set interfaces ethernet eth0 vif 0 firewall in name WAN_IN
set interfaces ethernet eth0 vif 0 firewall local name WAN_LOCAL
set interfaces ethernet eth0 vif 0 mac 'aa:bb:cc:dd:ee:ff'
set interfaces ethernet eth1 address 192.168.1.1/24
set interfaces ethernet eth1 description LAN
set interfaces ethernet eth1 duplex auto
set interfaces ethernet eth1 speed auto
set interfaces ethernet eth2 description 'AT&T router'
set interfaces ethernet eth2 duplex auto
set interfaces ethernet eth2 speed auto
set service nat rule 5010 description 'masquerade for WAN'
set service nat rule 5010 outbound-interface eth0.0
set service nat rule 5010 protocol all
set service nat rule 5010 type masquerade
set system offload ipv4 vlan enable
```

Update the mac address for `eth0 vif 0` to that of your AT&T router, or let `eap_proxy` do it with the `--set-mac` option. I prefer to just hard-code it in my config.

Note the `set system offload ipv4 vlan enable` command or you'll have horrible routing performance.

Don't forget to update the rest of your config to reference `eth0.0` as your WAN interface as needed.

Good luck. It works for me on my EdgeRouter Lite running EdgeOS v1.9.1.1.

## Usage

```
usage: eap_proxy [-h] [--ignore-wan-has-ip] [--ignore-wan-ping-gateway]
                 [--ignore-start] [--ignore-logoff] [--restart-dhcp]
                 [--set-mac] [--daemon] [--pidfile PIDFILE] [--syslog]
                 [--promiscuous] [--debug-packets]
                 IF_WAN IF_ROUTER

positional arguments:
  IF_WAN                interface of the AT&T ONT/WAN
  IF_ROUTER             interface of the AT&T router

optional arguments:
  -h, --help            show this help message and exit

ignoring router packets:
  --ignore-wan-has-ip   ignore router packets if IF_WAN.0 has an IP address
                        assigned
  --ignore-wan-ping-gateway
                        ignore router packets if IF_WAN.0 has a reachable
                        default gateway
  --ignore-start        always ignore EAPOL-Start from router
  --ignore-logoff       always ignore EAPOL-Logoff from router

configuring IF_WAN.0 VLAN:
  --restart-dhcp        restart IF_WAN.0 dhclient after receiving EAP-Success
                        if IF_WAN.0 does not have a reachable default gateway
  --set-mac             set IF_WAN.0 MAC to router's MAC

daemonization:
  --daemon              become a daemon; implies --syslog
  --pidfile PIDFILE     record pid to PIDFILE
  --syslog              log to syslog instead of stderr

debugging:
  --promiscuous         place interfaces into promiscuous mode instead of
                        multicast
  --debug-packets       print packets in hex format to assist with debugging
```
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

Update the MAC address for `eth0 vif 0` to that of your AT&T router, or let `eap_proxy` do it with the `--set-mac` option. I prefer to set it in my router config.

Note the `set system offload ipv4 vlan enable` command or you'll have horrible routing performance.

Don't forget to update the rest of your config to reference `eth0.0` as your WAN interface as needed.

I also have IPv6 working via 6rd. Here's the relevant configuration:

```
set interfaces tunnel tun0 6rd-prefix '2602:300::/28'
set interfaces tunnel tun0 6rd-default-gw '::12.83.49.81'
set interfaces tunnel tun0 address '2602:30x:xxxx:xxxx::/60'
set interfaces tunnel tun0 description 'AT&T 6rd tunnel'
set interfaces tunnel tun0 encapsulation sit
set interfaces tunnel tun0 firewall in ipv6-name WAN6_IN
set interfaces tunnel tun0 firewall local ipv6-name WAN6_LOCAL
set interfaces tunnel tun0 local-ip YY.YY.YY.YY
set interfaces tunnel tun0 multicast disable
set interfaces tunnel tun0 ttl 255
set system offload ipv6 forwarding enable
```

The `6rd-prefix` and `6rd-default-gw` should be the same for all AT&T customers that are using 6rd. I've heard some areas may be on native dual-stack, but my area is not. The `local-ip` is your DHCP-issued WAN IP. The `tun0 address` is your 6rd delegated prefix. It is based on your WAN IP and can be computed with this bit of python:

```
python -c 'import sys;a,b,c,d=map(int,sys.argv[1].split("."));print "2602:30%x:%x%02x%x:%x%02x0::/60" % (a>>4,a&15,b,c>>4,c&15,d)' 1.2.3.4
2602:300:1020:3040::/60
```

It may be possible to configure the tun0 interface via DHCPv6; I haven't tried.

Good luck. It works for me on my EdgeRouter Lite running EdgeOS v1.9.1.1.

## Usage

```
usage: eap_proxy [-h] [--ping-gateway] [--ignore-when-wan-up] [--ignore-start]
                 [--ignore-logoff] [--restart-dhcp] [--set-mac] [--daemon]
                 [--pidfile PIDFILE] [--syslog] [--promiscuous] [--debug]
                 [--debug-packets]
                 IF_WAN IF_ROUTER

positional arguments:
  IF_WAN                interface of the AT&T ONT/WAN
  IF_ROUTER             interface of the AT&T router

optional arguments:
  -h, --help            show this help message and exit

checking whether WAN is up:
  --ping-gateway        normally the WAN is considered up if IF_WAN.0 has an
                        IP address; this option additionally requires that
                        there is a default route gateway that responds to a
                        ping

ignoring router packets:
  --ignore-when-wan-up  ignore router packets when WAN is up (see --ping-
                        gateway)
  --ignore-start        always ignore EAPOL-Start from router
  --ignore-logoff       always ignore EAPOL-Logoff from router

configuring IF_WAN.0 VLAN:
  --restart-dhcp        check whether WAN is up after receiving EAP-Success on
                        IF_WAN (see --ping-gateway); if not, restart dhclient
                        on IF_WAN.0
  --set-mac             set IF_WAN.0's MAC (ether) address to router's MAC
                        address

daemonization:
  --daemon              become a daemon; implies --syslog
  --pidfile PIDFILE     record pid to PIDFILE
  --syslog              log to syslog instead of stderr

debugging:
  --promiscuous         place interfaces into promiscuous mode instead of
                        multicast
  --debug               enable debug-level logging
  --debug-packets       print packets in hex format to assist with debugging;
                        implies --debug
```

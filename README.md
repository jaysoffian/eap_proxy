# eap_proxy

Proxy EAP packets between interfaces on Ubiquiti Networks EdgeRouter™ products. Also works with UniFi® Security Gateway.

Inspired by 1x_prox as posted here:

<http://www.dslreports.com/forum/r30693618->

AT&T Residential Gateway Bypass - True bridge mode!

## Instructions (EdgeRouter)

- Copy `eap_proxy.sh` to `/config/scripts/post-config.d/eap_proxy.sh`
- Copy `eap_proxy.py` to `/config/scripts/eap_proxy.py`
- Adjust the settings in `eap_proxy.sh` as appropriate per the usage instructions below.

## Instructions (USG)

Please see <https://blog.taylorsmith.xyz/att-uverse-modem-bypass-unifi-usg/>

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

I previously had IPv6 working via 6rd before my area was on native dual-stack. Here's the relevant 6rd configuration from that time:

```
set interfaces tunnel tun0 6rd-prefix '2602:300::/28'
set interfaces tunnel tun0 6rd-default-gw '::12.83.49.81'
set interfaces tunnel tun0 address '2602:30x:xxxx:xxxx::1/60'
set interfaces tunnel tun0 description 'AT&T 6rd tunnel'
set interfaces tunnel tun0 encapsulation sit
set interfaces tunnel tun0 firewall in ipv6-name WAN6_IN
set interfaces tunnel tun0 firewall local ipv6-name WAN6_LOCAL
set interfaces tunnel tun0 local-ip YY.YY.YY.YY
set interfaces tunnel tun0 multicast disable
set interfaces tunnel tun0 ttl 255
set service dhcp-server use-dnsmasq enable
set service dns forwarding options enable-ra
set service dns forwarding options 'dhcp-range=::1,constructor:eth1,ra-names,86400'
set system offload ipv6 forwarding enable
```

The `6rd-prefix` and `6rd-default-gw` should be the same for all AT&T customers that are using 6rd. The `local-ip` is your DHCP-issued WAN IP. The `tun0 address` is your 6rd delegated prefix. It is based on your WAN IP and can be computed with this bit of python:

```
python -c 'import sys;a,b,c,d=map(int,sys.argv[1].split("."));print "2602:30%x:%x%02x%x:%x%02x0::1/60" % (a>>4,a&15,b,c>>4,c&15,d)' 1.2.3.4
2602:300:1020:3040::1/60
```

If you aren't already using `dnsmasq` for DHCP, you might want to use `radvd` instead. [See the example here](https://help.ubnt.com/hc/en-us/articles/204960044-EdgeRouter-Enable-IPv6-support-via-CLI) (it's the `router-advert` section).

For configuring IPv6 in areas that are on native dual-stack, please see the discussion in https://github.com/jaysoffian/eap_proxy/issues/3. FWIW, though I was able to get IPv6 to work correctly, I eventually disabled it for a couple reasons. First, AT&T's IPv6 network was flakey for me, and sometimes sites would randomly become unreachable. Second, even when IPv6 was working correctly, the latency for me to many sites was always significantly higher than over IPv4. YMMV.

Good luck. This proxy continues to work well for me. I originally developed it for use on an EdgeRouter Lite running EdgeOS v1.9.1.1. As of Sep 2018, I'm using it on an EdgeRouter 4 running EdgeOS v1.10.5. I know that it has also been used successfully on the ER-X and USG.

## Usage

```
usage: eap_proxy [-h] [--ping-gateway] [--ignore-when-wan-up] [--ignore-start]
                 [--ignore-logoff] [--restart-dhcp] [--set-mac]
                 [--vlan-id VLAN_ID] [--daemon] [--pidfile PIDFILE] [--syslog]
                 [--promiscuous] [--debug] [--debug-packets]
                 IF_WAN IF_ROUTER

positional arguments:
  IF_WAN                interface of the AT&T ONT/WAN
  IF_ROUTER             interface of the AT&T router

optional arguments:
  -h, --help            show this help message and exit

checking whether WAN is up:
  --ping-gateway        normally the WAN is considered up if the IF_WAN VLAN
                        has an address; this option additionally requires that
                        there is a default route gateway that responds to a
                        ping

ignoring router packets:
  --ignore-when-wan-up  ignore router packets when WAN is up (see --ping-
                        gateway)
  --ignore-start        always ignore EAPOL-Start from router
  --ignore-logoff       always ignore EAPOL-Logoff from router

configuring IF_WAN VLAN:
  --restart-dhcp        check whether WAN is up after receiving EAP-Success on
                        IF_WAN VLAN (see --ping-gateway); if not, restart
                        dhclient on IF_WAN VLAN
  --set-mac             set IF_WAN VLAN MAC (ether) address to router's MAC
                        address
  --vlan-id VLAN_ID     set IF_WAN VLAN ID (default is 0)

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

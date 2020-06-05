# eap_proxy

Proxy EAP packets between network interfaces. Compatible with:

- Ubiquiti Networks EdgeRouter™ products
- UniFi® Security Gateway
- Generic Linux systems

Inspired by [`1x_prox`](http://www.dslreports.com/forum/r30693618-) posted to the “[AT&T Residential Gateway Bypass - True bridge mode!](https://www.dslreports.com/forum/r29903721-AT-T-Residential-Gateway-Bypass-True-bridge-mode)” discussion in the “AT&T U-verse” DSLReports forum.

## Instructions (EdgeRouter)

1. Copy `eap_proxy.sh.example` to `eap_proxy.sh`.
2. Set `IF_WAN` and `IF_ROUTER` for your router's interfaces. The `CONFIG_OPTIONS` and `DAEMON_OPTIONS` should not normally need adjusting.
3. Either:
  - Run `copy_to_router.sh <name_of_your_router>`
  - Or
      - Copy `eap_proxy.sh` to `/config/scripts/post-config.d/eap_proxy.sh` and
      - Copy `eap_proxy.py` to `/config/scripts/eap_proxy.py`

## Instructions (USG)

Please see <https://blog.taylorsmith.xyz/att-uverse-modem-bypass-unifi-usg/>

## Instruction (Generic Linux)

Sorry, you're on your own for now, but see [#21](https://github.com/jaysoffian/eap_proxy/issues/21) for hints.

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
set firewall ipv6-name WAN6_IN default-action drop
set firewall ipv6-name WAN6_IN description 'WAN to internal'
set firewall ipv6-name WAN6_IN enable-default-log
set firewall ipv6-name WAN6_IN rule 10 action accept
set firewall ipv6-name WAN6_IN rule 10 description 'Allow established/related'
set firewall ipv6-name WAN6_IN rule 10 state established enable
set firewall ipv6-name WAN6_IN rule 10 state related enable
set firewall ipv6-name WAN6_IN rule 20 action drop
set firewall ipv6-name WAN6_IN rule 20 description 'Drop invalid state'
set firewall ipv6-name WAN6_IN rule 20 log enable
set firewall ipv6-name WAN6_IN rule 20 state invalid enable
set firewall ipv6-name WAN6_IN rule 30 action accept
set firewall ipv6-name WAN6_IN rule 30 description 'Allow ICMPv6 destination-unreachable'
set firewall ipv6-name WAN6_IN rule 30 icmpv6 type destination-unreachable
set firewall ipv6-name WAN6_IN rule 30 protocol icmpv6
set firewall ipv6-name WAN6_IN rule 31 action accept
set firewall ipv6-name WAN6_IN rule 31 description 'Allow ICMPv6 packet-too-big'
set firewall ipv6-name WAN6_IN rule 31 icmpv6 type packet-too-big
set firewall ipv6-name WAN6_IN rule 31 protocol icmpv6
set firewall ipv6-name WAN6_IN rule 32 action accept
set firewall ipv6-name WAN6_IN rule 32 description 'Allow ICMPv6 time-exceeded'
set firewall ipv6-name WAN6_IN rule 32 icmpv6 type time-exceeded
set firewall ipv6-name WAN6_IN rule 32 protocol icmpv6
set firewall ipv6-name WAN6_IN rule 33 action accept
set firewall ipv6-name WAN6_IN rule 33 description 'Allow ICMPv6 parameter-problem'
set firewall ipv6-name WAN6_IN rule 33 icmpv6 type parameter-problem
set firewall ipv6-name WAN6_IN rule 33 protocol icmpv6
set firewall ipv6-name WAN6_IN rule 34 action accept
set firewall ipv6-name WAN6_IN rule 34 description 'Allow ICMPv6 echo-request'
set firewall ipv6-name WAN6_IN rule 34 icmpv6 type echo-request
set firewall ipv6-name WAN6_IN rule 34 limit burst 1
set firewall ipv6-name WAN6_IN rule 34 limit rate 600/minute
set firewall ipv6-name WAN6_IN rule 34 protocol icmpv6
set firewall ipv6-name WAN6_IN rule 35 action accept
set firewall ipv6-name WAN6_IN rule 35 description 'Allow ICMPv6 echo-reply'
set firewall ipv6-name WAN6_IN rule 35 icmpv6 type echo-reply
set firewall ipv6-name WAN6_IN rule 35 limit burst 1
set firewall ipv6-name WAN6_IN rule 35 limit rate 600/minute
set firewall ipv6-name WAN6_IN rule 35 protocol icmpv6
set firewall ipv6-name WAN6_LOCAL default-action drop
set firewall ipv6-name WAN6_LOCAL description 'WAN to router'
set firewall ipv6-name WAN6_LOCAL enable-default-log
set firewall ipv6-name WAN6_LOCAL rule 10 action accept
set firewall ipv6-name WAN6_LOCAL rule 10 description 'Allow established/related'
set firewall ipv6-name WAN6_LOCAL rule 10 state established enable
set firewall ipv6-name WAN6_LOCAL rule 10 state related enable
set firewall ipv6-name WAN6_LOCAL rule 20 action drop
set firewall ipv6-name WAN6_LOCAL rule 20 description 'Drop invalid state'
set firewall ipv6-name WAN6_LOCAL rule 20 state invalid enable
set firewall ipv6-name WAN6_LOCAL rule 30 action accept
set firewall ipv6-name WAN6_LOCAL rule 30 description 'Allow ICMPv6 destination-unreachable'
set firewall ipv6-name WAN6_LOCAL rule 30 icmpv6 type destination-unreachable
set firewall ipv6-name WAN6_LOCAL rule 30 protocol icmpv6
set firewall ipv6-name WAN6_LOCAL rule 31 action accept
set firewall ipv6-name WAN6_LOCAL rule 31 description 'Allow ICMPv6 packet-too-big'
set firewall ipv6-name WAN6_LOCAL rule 31 icmpv6 type packet-too-big
set firewall ipv6-name WAN6_LOCAL rule 31 protocol icmpv6
set firewall ipv6-name WAN6_LOCAL rule 32 action accept
set firewall ipv6-name WAN6_LOCAL rule 32 description 'Allow ICMPv6 time-exceeded'
set firewall ipv6-name WAN6_LOCAL rule 32 icmpv6 type time-exceeded
set firewall ipv6-name WAN6_LOCAL rule 32 protocol icmpv6
set firewall ipv6-name WAN6_LOCAL rule 33 action accept
set firewall ipv6-name WAN6_LOCAL rule 33 description 'Allow ICMPv6 parameter-problem'
set firewall ipv6-name WAN6_LOCAL rule 33 icmpv6 type parameter-problem
set firewall ipv6-name WAN6_LOCAL rule 33 protocol icmpv6
set firewall ipv6-name WAN6_LOCAL rule 34 action accept
set firewall ipv6-name WAN6_LOCAL rule 34 description 'Allow ICMPv6 echo-request'
set firewall ipv6-name WAN6_LOCAL rule 34 icmpv6 type echo-request
set firewall ipv6-name WAN6_LOCAL rule 34 limit burst 5
set firewall ipv6-name WAN6_LOCAL rule 34 limit rate 5/second
set firewall ipv6-name WAN6_LOCAL rule 34 protocol icmpv6
set firewall ipv6-name WAN6_LOCAL rule 35 action accept
set firewall ipv6-name WAN6_LOCAL rule 35 description 'Allow ICMPv6 echo-reply'
set firewall ipv6-name WAN6_LOCAL rule 35 icmpv6 type echo-reply
set firewall ipv6-name WAN6_LOCAL rule 35 limit burst 5
set firewall ipv6-name WAN6_LOCAL rule 35 limit rate 5/second
set firewall ipv6-name WAN6_LOCAL rule 35 protocol icmpv6
set firewall ipv6-name WAN6_LOCAL rule 36 action accept
set firewall ipv6-name WAN6_LOCAL rule 36 description 'Allow ICMPv6 Router Advertisement'
set firewall ipv6-name WAN6_LOCAL rule 36 icmpv6 type router-advertisement
set firewall ipv6-name WAN6_LOCAL rule 36 protocol icmpv6
set firewall ipv6-name WAN6_LOCAL rule 37 action accept
set firewall ipv6-name WAN6_LOCAL rule 37 description 'Allow ICMPv6 Neighbor Solicitation'
set firewall ipv6-name WAN6_LOCAL rule 37 icmpv6 type neighbor-solicitation
set firewall ipv6-name WAN6_LOCAL rule 37 protocol icmpv6
set firewall ipv6-name WAN6_LOCAL rule 38 action accept
set firewall ipv6-name WAN6_LOCAL rule 38 description 'Allow ICMPv6 Neighbor Advertisement'
set firewall ipv6-name WAN6_LOCAL rule 38 icmpv6 type neighbor-advertisement
set firewall ipv6-name WAN6_LOCAL rule 38 protocol icmpv6
set firewall ipv6-name WAN6_LOCAL rule 50 action accept
set firewall ipv6-name WAN6_LOCAL rule 50 description 'Allow DHCPv6'
set firewall ipv6-name WAN6_LOCAL rule 50 destination port 546
set firewall ipv6-name WAN6_LOCAL rule 50 protocol udp
set firewall ipv6-name WAN6_LOCAL rule 50 source port 547
set firewall ipv6-receive-redirects disable
set firewall ipv6-src-route disable
set service dhcp-server use-dnsmasq enable
set service dns forwarding options enable-ra
set service dns forwarding options 'dhcp-range=::1,constructor:eth1,ra-names,86400'
set interfaces ethernet eth0 vif 0 dhcpv6-pd duid 'xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx'
set interfaces ethernet eth0 vif 0 dhcpv6-pd pd 1 interface eth1 host-address '::1'
set interfaces ethernet eth0 vif 0 dhcpv6-pd pd 1 interface eth1 no-dns
set interfaces ethernet eth0 vif 0 dhcpv6-pd pd 1 interface eth1 prefix-id ':0'
set interfaces ethernet eth0 vif 0 dhcpv6-pd pd 1 interface eth1 service slaac
set interfaces ethernet eth0 vif 0 dhcpv6-pd pd 1 prefix-length 60
set interfaces ethernet eth0 vif 0 dhcpv6-pd prefix-only
set interfaces ethernet eth0 vif 0 dhcpv6-pd rapid-commit disable
set interfaces ethernet eth0 vif 0 firewall in ipv6-name WAN6_IN
set interfaces ethernet eth0 vif 0 firewall local ipv6-name WAN6_LOCAL
set interfaces ethernet eth0 vif 0 ipv6 dup-addr-detect-transmits 1
set system offload ipv6 forwarding enable
set system offload ipv6 vlan enable
```

Update the MAC address for `eth0 vif 0` to that of your AT&T router, or let `eap_proxy` do it with the `--set-mac` option. I prefer to set it in my router config.

Note the `set system offload ipv4 vlan enable` command or you'll have horrible routing performance.

Don't forget to update the rest of your config to reference `eth0.0` as your WAN interface as needed.

For IPv6, be sure to change the duid value to the duid of your AT&T router, or wait ~2 weeks for the lease to expire to get a fresh lease. You can sniff the traffic from your AT&T router to find the duid, or generate one with a script like gen-duid.sh from pfatt on github.

For firewall rules, note that the setup wizard creates rules named WANv6_* if you check the box to enable IPv6, whereas the above rules are WAN6_*.

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
usage: eap_proxy [-h] [--ping-gateway] [--ping-ip PING_IP]
                 [--ignore-when-wan-up] [--ignore-start] [--ignore-logoff]
                 [--restart-dhcp] [--set-mac] [--vlan-id VLAN_ID] [--daemon]
                 [--pidfile PIDFILE] [--syslog] [--run-as USER[:GROUP]]
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
                        there is a route via IF_WAN with a gateway (next-hop)
                        that responds to a ping
  --ping-ip PING_IP     normally the WAN is considered up if the IF_WAN VLAN
                        has an address; this option additionally requires that
                        PING_IP responds to a ping

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

process management:
  --daemon              fork into background and attempt to run forever until
                        killed; implies --syslog
  --pidfile PIDFILE     record pid to PIDFILE
  --syslog              log to syslog instead of stderr
  --run-as USER[:GROUP]
                        switch to USER[:GROUP] after opening sockets;
                        incompatible with --daemon

debugging:
  --promiscuous         place interfaces into promiscuous mode instead of
                        multicast
  --debug               enable debug-level logging
  --debug-packets       print packets in hex format to assist with debugging;
                        implies --debug
```

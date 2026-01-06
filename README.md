# End of Life

I originally developed `eap_proxy` in 2017 for use on an EdgeRouter Lite running EdgeOS v1.9.1.1 where it worked well for me for many years. In 2024, I switched to a Dream Machine Pro using [wpasupplicant to bypass the AT&T router](https://old.reddit.com/r/Ubiquiti/comments/18rc0ag/att_modem_bypass_and_unifios_32x_guide/). 

Since I no longer use the proxy, nor have anyway to test it, it is now end of life.

# eap_proxy

Proxy EAP packets between network interfaces. Compatible with:

- Ubiquiti Networks EdgeRouter™ products
- UniFi® Security Gateway
- Unifi® Dream Machine (Unifi OS 3.x+) 
- Generic Linux systems

Inspired by [`1x_prox`](https://web.archive.org/web/20201112025501/https://www.dslreports.com/forum/r30693618-) posted to the “[AT&T Residential Gateway Bypass - True bridge mode!](https://web.archive.org/web/20241209153049/https://www.dslreports.com/forum/r29903721-AT-T-Residential-Gateway-Bypass-True-bridge-mode)” discussion in the “AT&T U-verse” DSLReports forum.

This also works with AU Japan 802.1x (AU "White Box").

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

## Instructions Unifi OS Devices (UDM Pro & Variants, NOT UXG-Pro) 

Notes: 
1. This will require using one of your SFP+ Ports, and an SFP+ to Ethernet interface.
2. This may or may not survive OS upgrades, it will survive Unifi App Upgrades.

eth8 = Ethernet Uplink Port (Separated "WAN" port on the UDM)

eth9 = Top SFP+ Port

eth10 = Bottom SFP+ Port


Instructions:   
1. Enable SSH on your UDM.
2. Clone the MAC Address from the provided router to the WAN port on the UDM (Settings -> Internet -> WAN 1/2 -> MAC Address Clone).
3. Disconnect the UDM from the provided router & the provided router from the ONT.
4. Copy an archive of the repo to the UDM and extract it to /etc/eap_proxy/ (you will need to create this directory).
5. Test the setup:

   ```python /etc/eap_proxy/eap_proxy.py --ignore-when-wan-up --ignore-logoff --ping-gateway eth8 eth9``` (or eth10).

   Connect eth8 to the ONT, connect the router to eth9/eth10.
   
After a few minutes, you should see an output similar to below:

```
Jul 08 19:52:12 UDMPRO python[1520690]: [2024-07-08 19:52:12,793]: starting proxy_loop
Jul 08 20:32:42 UDMPRO python[1520690]: [2024-07-08 20:32:42,135]: eth9: 08:33:ed:XX:XX:XX > 01:80:c2:XX:XX:XX, EAPOL start (1) v1, len 0 > eth8
Jul 08 20:32:42 UDMPRO python[1520690]: [2024-07-08 20:32:42,150]: eth8: 00:25:5c:XX:XX:XX > 08:33:ed:XX:XX:XX, EAP packet (0) v1, len 5, Request (1) id 6, len 5 [1] > eth9
Jul 08 20:32:42 UDMPRO python[1520690]: [2024-07-08 20:32:42,156]: eth9: 08:33:ed:XX:XX:XX > 01:80:c2:XX:XX:XX, EAP packet (0) v1, len 17, Response (2) id 6, len 17 [13] > eth8
Jul 08 20:32:42 UDMPRO python[1520690]: [2024-07-08 20:32:42,171]: eth8: 00:25:5c:XX:XX:XX > 08:33:ed:XX:XX:XX, EAP packet (0) v1, len 28, Request (1) id 7, len 28 [24] > eth9
Jul 08 20:32:42 UDMPRO python[1520690]: [2024-07-08 20:32:42,177]: eth9: 08:33:ed:XX:XX:XX > 01:80:c2:XX:XX:XX, EAP packet (0) v1, len 34, Response (2) id 7, len 34 [30] > eth8
Jul 08 20:32:42 UDMPRO python[1520690]: [2024-07-08 20:32:42,211]: eth8: 00:25:5c:XX:XX:XX > 08:33:ed:XX:XX:XX, EAP packet (0) v1, len 4, Success (3) id 8, len 4 [0] > eth9
```

 6. Once you confirm the UDM receives an IP and you can reach the internet, setup a service file so that systemd can manage the script.
 7. Using a text editor, create the file ```/etc/systemd/system/eap_proxy.service```

    ```
    [Unit]
    Description=EAP_PROXY
    After=network.target
    StartLimitIntervalSec=0

    [Service]
    WorkingDirectory=/etc/eap_proxy
    Type=simple
    Restart=always
    RestartSec=1
    ExecStart=/usr/bin/python /etc/eap_proxy/eap_proxy.py --ignore-when-wan-up --ignore-logoff --ping-gateway eth8 eth9

    [Install]
    WantedBy=multi-user.target
    ```

 8. Run the following commands to enable & start the service.

    ```systemctl enable eap_proxy.service```
    
    ```systemctl start eap_proxy```
    
 10. Unplug & replug the cable from the ONT to the UDM.

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

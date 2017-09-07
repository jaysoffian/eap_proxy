#!/bin/sh
# Startup script for eap_proxy.py. Place eap_proxy.py in /config/scripts and
# place this in /config/scripts/post-config.d
#
IF_WAN=eth0
IF_ROUTER=eth2
CONFIG_OPTIONS=(--restart-dhcp --ignore-wan-has-ip --ignore-logoff)
DAEMON_OPTIONS=(--daemon --pidfile /var/run/eap_proxy.pid --syslog)
/usr/bin/python /config/scripts/eap_proxy.py \
    "$IF_WAN" "$IF_ROUTER" "${CONFIG_OPTIONS[@]}" "${DAEMON_OPTIONS[@]}" &

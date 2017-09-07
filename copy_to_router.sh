#!/bin/sh
# just a helpful script for copying everything over to the router; assumes
# "router" resolves to your EdgeRouter.
set -ex
scp eap_proxy.py router:/config/scripts
scp eap_proxy.sh router:/config/scripts/post-config.d
scp eap_tcpdump.sh router:

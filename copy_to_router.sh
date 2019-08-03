#!/bin/sh
# Copies eap_proxy.sh and eap_proxy.py to your EdgeRouter.

if ! test -f eap_proxy.sh; then
  echo >&2 "Please copy eap_proxy.sh.example to eap_proxy.sh and edit it per"
  echo >&2 "the README.md before running this script."
  exit 1
fi

if test $# -ne 1; then
  echo >&2 "Usage: copy_to_router.sh <router>"
  exit 1
fi

set -ex
ssh "$1" mkdir -p eap_proxy
scp eap_proxy.sh eap_proxy.py "$1:eap_proxy/"
ssh "$1" "
  sudo mkdir -p /config/scripts /config/scripts/post-config.d &&
  sudo cp eap_proxy/eap_proxy.py /config/scripts/ &&
  sudo cp eap_proxy/eap_proxy.sh /config/scripts/post-config.d/ &&
  sudo chown root:vyattacfg \
    /config/scripts/eap_proxy.py \
    /config/scripts/post-config.d/eap_proxy.sh &&
  sudo chmod 755 \
    /config/scripts/eap_proxy.py \
    /config/scripts/post-config.d/eap_proxy.sh"

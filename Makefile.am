cfgdir = $(datadir)/vyatta-cfg/templates
opdir = $(datadir)/vyatta-op/templates
curverdir = $(sysconfdir)/config-migrate/current
bin_sudo_usersdir = $(bindir)/sudo-users

vprefix = /opt/vyatta
vsbindir = $(vprefix)/sbin

sbin_SCRIPTS =
sbin_SCRIPTS += scripts/eap_proxy.py
sbin_SCRIPTS += scripts/vyatta-service-eap-proxy-update.sh

bin_sudo_users_SCRIPTS =

curver_DATA = 

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates-cfg; $(cpiop) $(DESTDIR)$(cfgdir)

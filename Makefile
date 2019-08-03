all: black lint

black:
	black eap_proxy.py

lint:
	pylint eap_proxy.py

.PHONY: all black lint

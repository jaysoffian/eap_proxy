"Setup script for eap_proxy."
from setuptools import setup


setup(
    name="eap_proxy",
    version="1.0",
    description="Proxy EAP packets between interfaces on Linux-based routers.",
    url="https://github.com/jaysoffian/eap_proxy",
    author="Jay Soffian",
    license="BSD",
    py_modules=["eap_proxy"],
    entry_points={"console_scripts": ["eap_proxy=eap_proxy:main"]},
)

"""Read the Scanner Tool host's physical IPv4 interface configuration."""

import ipaddress
import json
import locale
import re
import subprocess
import threading
import time

_CACHE_TTL = 60.0
_cache_lock = threading.Lock()
_cache: tuple[str, str, float] | None = None


def select_local_ipv4(interfaces, preferred="enp4s0") -> tuple[str, str]:
    candidates = []
    for interface in interfaces:
        name = interface.get("ifname", "")
        if _virtual(name) or interface.get("operstate") == "DOWN":
            continue
        for addr in interface.get("addr_info", []):
            if addr.get("family") != "inet" or addr.get("scope") != "global":
                continue
            ip = ipaddress.ip_address(addr["local"])
            if ip.version == 4 and not (ip.is_loopback or ip.is_link_local or ip.is_unspecified):
                candidates.append((str(ip), name))
    preferred_candidates = [item for item in candidates if item[1] == preferred]
    choices = list(dict.fromkeys(preferred_candidates or candidates))
    if len(choices) != 1:
        raise ValueError("无法唯一确认非虚拟网卡的本机 IPv4 地址，请明确提供目标 IP")
    return choices[0]


def detect_local_ip() -> tuple[str, str]:
    """Prefer enp4s0's IPv4 and never return a Docker/virtual interface."""
    config = detect_local_configuration()
    return config["ipv4"], config["interface"]


def detect_local_configuration() -> dict[str, str]:
    interfaces = json.loads(_run("ip", "-j", "-4", "addr", "show"))
    address, interface = select_local_ipv4(interfaces)
    networks = {
        str(ipaddress.ip_network(f"{address}/{addr['prefixlen']}", strict=False))
        for item in interfaces if item.get("ifname") == interface
        for addr in item.get("addr_info", [])
        if addr.get("family") == "inet" and addr.get("local") == address
    }
    if len(networks) != 1:
        raise ValueError("无法唯一确认本机 IPv4 对应的网段")
    return {"ipv4": address, "interface": interface, "network": networks.pop()}


def _run(*command):
    result = subprocess.run(command, capture_output=True, timeout=10, check=True)
    return result.stdout.decode(locale.getpreferredencoding(False), errors="replace")


def _virtual(name):
    return bool(re.search(r"docker|veth|virbr|br-|loopback|vmware|virtualbox|tun\d|tap\d|^lo$", name, re.I))


def parse_linux(routes, interfaces):
    default_devices = {r.get("dev") for r in routes if r.get("dst") == "default"}
    candidates = []
    for interface in interfaces:
        name = interface.get("ifname", "")
        if name not in default_devices or _virtual(name):
            continue
        for addr in interface.get("addr_info", []):
            if addr.get("family") == "inet" and addr.get("scope") == "global":
                candidates.append((name, addr["local"], str(addr["prefixlen"])))
    return candidates


def detect_local_network(ttl: float = _CACHE_TTL, refresh: bool = False) -> tuple[str, str]:
    """Return (network, interface), cached for ``ttl`` seconds."""
    global _cache
    now = time.monotonic()
    with _cache_lock:
        cached = _cache
    if not refresh and cached and now - cached[2] < ttl:
        return cached[0], cached[1]
    network, interface = _detect_uncached()
    with _cache_lock:
        _cache = (network, interface, time.monotonic())
    return network, interface


def _detect_uncached() -> tuple[str, str]:
    config = detect_local_configuration()
    return config["network"], config["interface"]

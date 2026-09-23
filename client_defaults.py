"""Client-side fault tolerance for scan parameters.

参数缺失或非法时，客户端在这里补齐默认值，避免把空参数直接发给扫描工具：

* 没给网段 -> 使用配置或 get_local_network 已确认的网段，否则提示先查询目标
* 没给端口 -> 常见端口列表（也支持 top / web / all 等别名）
* 没给 IP   -> 已知网段内发现的存活主机；发现失败时提示明确目标
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.parse

COMMON_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
    "1433,1521,2049,3306,3389,5432,5900,6379,8000,8080,8443,9200,27017"
)
WEB_PORTS = "80,81,443,8080,8443"
TOP_PORTS = (
    "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,"
    "143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,"
    "587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,"
    "1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,"
    "4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,"
    "6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,"
    "10000,32768,49152,49153,49154,49155,49156,49157"
)

MAX_PREFIX = 24
MAX_HOSTS = 32
MAX_NETWORK_HOST_CALLS = 256

NETWORK_TOOL = "nmap_scan"
HOST_TOOLS = {
    "ssl_check": "target",
    "whois_lookup": "target",
    "ping_target": "target",
    "traceroute_target": "target",
    "nikto_scan": "target",
    "nuclei_scan": "target",
    "zap_scan": "target",
}
URL_TOOLS = {"curl_headers": "url", "sqlmap_scan": "url"}
HOSTNAME_TOOLS = {"dns_recon": "domain", "subfinder_enum": "domain"}

_PORT_ALIASES = {
    "common": COMMON_PORTS,
    "default": COMMON_PORTS,
    "默认": COMMON_PORTS,
    "top": TOP_PORTS,
    "top100": TOP_PORTS,
    "web": WEB_PORTS,
    "http": WEB_PORTS,
    "all": "1-65535",
    "full": "1-65535",
    "全部": "1-65535",
}

_HOST_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?")
_WILDCARD_OCTET = re.compile(r"[xX*]")
_RANGE_OCTET = re.compile(r"(\d{1,3})\s*-\s*(\d{1,3})")
_NMAP_REPORT = re.compile(r"Nmap scan report for (?:[^\s(]+ \()?([0-9A-Fa-f:.]+)\)?", re.M)
_NMAP_OPEN = re.compile(r"^\d+/(?:tcp|udp)\s+open(?=\s|$)", re.M)


def is_ip(text: object) -> bool:
    try:
        ipaddress.ip_address(str(text))
    except ValueError:
        return False
    return True


def clean_network(value: object) -> str | None:
    """把用户/LLM 给的网段规范成 CIDR；无法识别时返回 None。"""
    return clean_network_note(value)[0]


def clean_network_note(value: object) -> tuple[str | None, str | None]:
    """解析网段，并说明通配符写法被展开成了什么。

    支持 192.168.88.* / 192.168.88.x / 192.168.88.1-254 这类简写，
    返回 (cidr, note)；无法识别时返回 (None, None)。
    """
    if value is None:
        return None, None
    text = str(value).strip().strip("\"'")
    if not text or any(char.isspace() for char in text):
        return None, None
    try:
        return str(ipaddress.ip_network(text, strict=False)), None
    except ValueError:
        return _parse_shorthand(text)


def network_from_host_value(value: object) -> tuple[str | None, str | None]:
    """Return a multi-address network when a single-host argument contains one."""
    if value is None:
        return None, None
    text = str(value).strip().strip("\"'")
    # A bare IP is a valid single host, not a network expansion request.
    if "/" not in text and not _WILDCARD_OCTET.search(text) and not _RANGE_OCTET.search(text):
        return None, None
    network, note = clean_network_note(text)
    if network is None:
        return None, None
    parsed = ipaddress.ip_network(network, strict=False)
    if parsed.num_addresses <= 1:
        return None, None
    return str(parsed), note


def network_hosts(value: str, limit: int = MAX_NETWORK_HOST_CALLS) -> list[str]:
    """Expand usable addresses from a CIDR while enforcing a hard fan-out limit."""
    network = ipaddress.ip_network(value, strict=False)
    usable = network.num_addresses
    if network.version == 4 and network.prefixlen < 31:
        usable -= 2
    if usable > limit:
        raise ValueError(
            f"network {network} contains {usable} usable hosts; maximum fan-out is {limit}"
        )
    return [str(host) for host in network.hosts()]


def _parse_shorthand(text: str) -> tuple[str | None, str | None]:
    """把通配符/区间写法解析成 CIDR：192.168.88.* -> 192.168.88.0/24。"""
    parts = text.split(".")
    if len(parts) != 4:
        return None, None
    if any(_WILDCARD_OCTET.fullmatch(part) for part in parts):
        if not all(_WILDCARD_OCTET.fullmatch(part) or part.isdigit() for part in parts):
            return None, None
        first = next(index for index, part in enumerate(parts) if _WILDCARD_OCTET.fullmatch(part))
        # 只支持连续到末尾的通配符，例如 192.168.*.5 不解析
        if not all(_WILDCARD_OCTET.fullmatch(part) for part in parts[first:]):
            return None, None
        if any(not 0 <= int(part) <= 255 for part in parts[:first]):
            return None, None
        base = ".".join(parts[:first] + ["0"] * (4 - first))
        cidr = str(ipaddress.ip_network(f"{base}/{first * 8}", strict=False))
        return cidr, f"已将 {text} 解析为 {cidr}"
    if all(part.isdigit() for part in parts[:3]) and _RANGE_OCTET.fullmatch(parts[3]):
        if any(not 0 <= int(part) <= 255 for part in parts[:3]):
            return None, None
        start, end = (int(value) for value in parts[3].split("-"))
        if not 0 <= start <= end <= 255:
            return None, None
        network = _covering_network(parts[:3], start, end)
        note = f"已将 {text} 解析为 {network}"
        if network.num_addresses != end - start + 1:
            note += "（最小覆盖网段，可能包含区间外地址）"
        return str(network), note
    return None, None


def _covering_network(octets: list[str], start: int, end: int) -> ipaddress.IPv4Network:
    """返回能覆盖最后一字节 [start, end] 的最小 IPv4 网段。"""
    first = ipaddress.ip_address(".".join([*octets, str(start)]))
    last = ipaddress.ip_address(".".join([*octets, str(end)]))
    common = 0
    for left, right in zip(first.packed, last.packed):
        if left != right:
            break
        common += 8
    if common < 32:
        diff = first.packed[common // 8] ^ last.packed[common // 8]
        common += 8 - diff.bit_length()
    return ipaddress.ip_network(f"{first}/{common}", strict=False)


def narrow_to_prefix(value: str, max_prefix: int = MAX_PREFIX) -> str:
    """服务端只接受 /24 及更小的网段，过大的网段自动收窄。"""
    network = ipaddress.ip_network(value, strict=False)
    if network.prefixlen >= max_prefix:
        return str(network)
    return str(ipaddress.ip_network(f"{network.network_address}/{max_prefix}", strict=False))


def clean_host(value: object, keep_port: bool = False) -> str | None:
    """提取主机（或主机:端口），去掉协议、路径、查询串等；无法识别时返回 None。"""
    if value is None:
        return None
    text = str(value).strip().strip("\"'")
    if not text or any(char.isspace() for char in text):
        return None
    if "://" in text:
        text = text.split("://", 1)[1]
    text = re.split(r"[/?#]", text, 1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if is_ip(text):
        return text
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
        if not is_ip(host) or (port and not port.isdigit()):
            return None
        return f"[{host}]:{port}" if keep_port and port else host
    host, sep, port = text.rpartition(":")
    if sep and port.isdigit():
        if not (_HOST_PATTERN.fullmatch(host) or is_ip(host)):
            return None
        return f"{host}:{port}" if keep_port else host
    text = text.strip(":").rstrip(".")
    if not text or not (_HOST_PATTERN.fullmatch(text) or is_ip(text)):
        return None
    return text


def ensure_url(host: str) -> str:
    return host if "://" in host else f"http://{host}"


def server_host_from_url(url: str | None) -> str | None:
    if not url:
        return None
    text = url if "://" in url else f"http://{url}"
    try:
        return urllib.parse.urlsplit(text).hostname
    except ValueError:
        return None


def default_network_from_host(host: str | None, max_prefix: int = MAX_PREFIX) -> str | None:
    """用服务器地址推断默认网段，例如 192.168.88.233 -> 192.168.88.0/24。"""
    if not host or not is_ip(host):
        return None
    ip = ipaddress.ip_address(host)
    if ip.version != 4 or ip.is_loopback or ip.is_unspecified or ip.is_link_local:
        return None
    return narrow_to_prefix(f"{ip}/{max_prefix}")


def _split_tokens(value: object) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        tokens: list[str] = []
        for item in value:
            tokens.extend(_split_tokens(item))
        return tokens
    return [token for token in re.split(r"[,;\s]+", str(value)) if token]


def _expand_aliases(tokens: list[str], depth: int = 0) -> list[str]:
    if depth > 3:
        return tokens
    expanded: list[str] = []
    for token in tokens:
        alias = _PORT_ALIASES.get(token.strip().lower())
        if alias is None:
            expanded.append(token)
        else:
            expanded.extend(_expand_aliases(_split_tokens(alias), depth + 1))
    return expanded


def _merge_intervals(intervals: list[list[int]]) -> list[list[int]]:
    merged: list[list[int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def normalize_ports(value: object, default: str = COMMON_PORTS) -> tuple[str, str | None]:
    """规范化端口表达；缺失或非法时回退到 default。

    返回 (ports, note)：note 非空表示发生了替换或归一化，供调用方提示用户。
    """
    empty = value is None or (isinstance(value, str) and not value.strip())
    if empty or (isinstance(value, (list, tuple, set)) and not value):
        return default, f"未指定端口，使用默认端口 {default}"
    if isinstance(value, str):
        alias = _PORT_ALIASES.get(value.strip().lower())
        if alias is not None:
            return alias, None
    intervals: list[list[int]] = []
    for token in _expand_aliases(_split_tokens(value)):
        match = re.fullmatch(r"(\d{1,5})(?:\s*-\s*(\d{1,5}))?", token)
        if match is None:
            return default, f"端口 {value!r} 无法识别，已回退到默认端口 {default}"
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if not 1 <= start <= end <= 65535:
            return default, f"端口 {value!r} 超出 1-65535 或区间倒序，已回退到默认端口 {default}"
        intervals.append([start, end])
    text = ",".join(
        f"{start}-{end}" if start != end else str(start)
        for start, end in _merge_intervals(intervals)
    )
    note = None if text == str(value).strip() else f"端口已归一化为 {text}"
    return text, note


def prepare_tool_call(tool_name: str, args: dict | None):
    """规范化已提供的参数，并指出还缺哪种默认值。

    返回 (prepared_args, notes, pending)，pending 取值：
    None 表示参数齐全，"network" 表示缺网段，"host" 表示缺 IP/主机，
    "host_network" 表示单主机参数收到了网段，"hostname" 表示缺域名。
    未覆盖的工具原样返回。
    """
    prepared = dict(args or {})
    notes: list[str] = []
    if tool_name == NETWORK_TOOL:
        target, shorthand_note = clean_network_note(prepared.get("target"))
        pending = None
        if target is None:
            prepared.pop("target", None)
            pending = "network"
        else:
            if shorthand_note:
                notes.append(shorthand_note)
            narrowed = narrow_to_prefix(target)
            if narrowed != target:
                notes.append(f"网段已自动收窄为 {narrowed}（服务端最大允许 /{MAX_PREFIX}）")
            prepared["target"] = narrowed
        ports, note = normalize_ports(prepared.get("ports"))
        prepared["ports"] = ports
        if note:
            notes.append(note)
        return prepared, notes, pending
    if tool_name in HOST_TOOLS:
        param = HOST_TOOLS[tool_name]
        network, network_note = network_from_host_value(prepared.get(param))
        if network is not None:
            prepared.pop(param, None)
            prepared["_target_network"] = network
            if network_note:
                notes.append(network_note)
            return prepared, notes, "host_network"
        value = clean_host(prepared.get(param))
        if value is None:
            prepared.pop(param, None)
            return prepared, notes, "host"
        prepared[param] = value
        return prepared, notes, None
    if tool_name in URL_TOOLS:
        param = URL_TOOLS[tool_name]
        raw = str(prepared.get(param) or "").strip().strip("\"'")
        network, network_note = network_from_host_value(raw)
        if network is not None:
            prepared.pop(param, None)
            prepared["_target_network"] = network
            if network_note:
                notes.append(network_note)
            return prepared, notes, "host_network"
        value = clean_host(raw, keep_port=True)
        if value is None:
            prepared.pop(param, None)
            return prepared, notes, "host"
        prepared[param] = raw if "://" in raw else ensure_url(value)
        return prepared, notes, None
    if tool_name in HOSTNAME_TOOLS:
        param = HOSTNAME_TOOLS[tool_name]
        value = clean_host(prepared.get(param))
        if value is None:
            prepared.pop(param, None)
            return prepared, notes, "hostname"
        prepared[param] = value
        return prepared, notes, None
    return prepared, notes, None


def with_host(tool_name: str, args: dict, host: str) -> tuple[str, dict]:
    """把单个主机填进对应工具的参数字段。"""
    if tool_name in URL_TOOLS:
        return host, {**args, URL_TOOLS[tool_name]: ensure_url(host)}
    if tool_name in HOST_TOOLS:
        return host, {**args, HOST_TOOLS[tool_name]: host}
    if tool_name in HOSTNAME_TOOLS:
        return host, {**args, HOSTNAME_TOOLS[tool_name]: host}
    return host, dict(args)


def expand_host_calls(tool_name: str, args: dict, hosts: list[str]) -> list[tuple[str, dict]]:
    """按主机列表展开成多次调用，返回 (label, args) 列表。"""
    return [with_host(tool_name, args, host) for host in hosts]


def extract_live_hosts(text: str) -> list[str]:
    """从 host_discovery 的 JSON 结果或 nmap 原始输出里提取存活主机。"""
    hosts: list[str] = []
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        data = None
    if isinstance(data, dict):
        raw = data.get("hosts") or data.get("live_hosts") or []
        hosts = [str(item) for item in raw if item]
        if not hosts and isinstance(data.get("output"), str):
            return extract_live_hosts(data["output"])
    elif isinstance(data, list):
        hosts = [str(item) for item in data if item]
    if not hosts:
        report = None
        opened = False
        for line in text.splitlines():
            match = _NMAP_REPORT.match(line)
            if match:
                if report and opened:
                    hosts.append(report)
                report, opened = match.group(1), False
            elif report and _NMAP_OPEN.match(line):
                opened = True
        if report and opened:
            hosts.append(report)
    unique: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        if host not in seen:
            seen.add(host)
            unique.append(host)
    return unique

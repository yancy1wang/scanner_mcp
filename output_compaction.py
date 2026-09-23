"""Deterministic, tool-aware compression for scanner results sent to the LLM."""

from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from typing import Iterable

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
MAX_ITEM_CHARS = 6000
DEFAULT_BUDGET = 28000


def _payload(text: object) -> dict:
    raw = str(text)
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return {"output": raw}
    return data if isinstance(data, dict) else {"output": data}


def _text(data: dict) -> str:
    value = data.get("output")
    if value in (None, ""):
        value = data.get("stderr") or data.get("error") or ""
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return ANSI.sub("", value).replace("\r", "")


def _lines(text: str, limit: int = 200) -> list[str]:
    result, seen = [], set()
    for raw in text.splitlines():
        line = " ".join(raw.strip().split())
        if not line or line in seen:
            continue
        seen.add(line)
        result.append(line)
        if len(result) == limit:
            break
    return result


def _bounded(lines: Iterable[str], source_count: int | None = None, limit: int = MAX_ITEM_CHARS) -> str:
    kept, used = [], 0
    values = [line for line in lines if line]
    for line in values:
        if used + len(line) + 1 > limit:
            break
        kept.append(line)
        used += len(line) + 1
    omitted = (source_count if source_count is not None else len(values)) - len(kept)
    if omitted > 0:
        kept.append(f"[COMPRESSED: {omitted} additional records omitted from this tool result]")
    return "\n".join(kept) or "NO_OUTPUT"


def _status(data: dict) -> str:
    if data.get("success") is True:
        return "OK"
    if data.get("success") is False or data.get("status") in {
        "error", "failed", "timeout", "rejected", "unavailable", "disconnected"
    }:
        return "FAILED"
    return str(data.get("status") or "UNKNOWN").upper()


def _ping(data: dict, output: str) -> str:
    loss = re.search(r"([0-9.]+)%\s*packet loss", output, re.I)
    timing = re.search(r"(?:rtt|round-trip).*?=\s*[0-9.]+/([0-9.]+)/", output, re.I)
    unreachable = bool(re.search(r"100(?:\.0+)?%\s*packet loss|destination .*unreachable|100% loss", output, re.I))
    up = data.get("success") is True and not unreachable
    state = "UP" if up else "DOWN" if unreachable or data.get("exit_code") == 1 else "ERROR"
    fields = [state]
    if loss:
        fields.append(f"loss={loss.group(1)}%")
    if timing:
        fields.append(f"avg={timing.group(1)}ms")
    if state == "ERROR":
        detail = next(iter(_lines(output, 1)), str(data.get("error") or "unknown error"))
        fields.append(detail[:300])
    return " ".join(fields)


def _nmap(data: dict, output: str) -> str:
    hosts: dict[str, list[str]] = defaultdict(list)
    current = str(data.get("target") or "target")
    for line in output.splitlines():
        report = re.search(r"Nmap scan report for (?:.*\()?([0-9A-Fa-f:.]+)\)?$", line.strip())
        if report:
            current = report.group(1)
            hosts.setdefault(current, [])
            continue
        opened = re.match(r"\s*(\d+)/(tcp|udp)\s+open\s*(\S+)?\s*(.*)", line)
        if opened:
            service = (opened.group(3) or "unknown")
            version = " ".join(opened.group(4).split())[:120]
            value = f"{opened.group(1)}/{opened.group(2)}:{service}"
            if version:
                value += f"({version})"
            hosts[current].append(value)
    records = [f"{host} open={','.join(ports) if ports else 'none'}" for host, ports in hosts.items()]
    if not records:
        records = [f"{_status(data)} " + (next(iter(_lines(output, 1)), "no open ports reported"))]
    return _bounded(records, len(records))


def _marked_sections(output: str) -> list[str]:
    section, result = "records", []
    for line in _lines(output, 300):
        mark = re.match(r"===\s*(.*?)\s*===$", line)
        if mark:
            section = mark.group(1)
        else:
            result.append(f"{section}:{line}")
    return result


def _whois(output: str) -> list[str]:
    keys = r"domain name|netname|netrange|cidr|inetnum|orgname|organization|country|registrar|creation date|updated date|registry expiry date|name server|status|descr|origin"
    selected = [line for line in _lines(output, 250) if re.match(rf"(?:{keys})\s*:", line, re.I)]
    return selected or _lines(output, 20)


def _tls(output: str) -> list[str]:
    patterns = (
        r"^(?:subject|issuer|notBefore|notAfter|serial|SHA256 Fingerprint)\s*=",
        r"^(?:Protocol|Cipher|Verify return code|Verification error|Server public key)\s*:",
        r"certificate has expired|hostname mismatch|self[- ]signed|unable to get local issuer|no peer certificate|connection refused|wrong version number",
    )
    selected = [line for line in _lines(output, 300) if any(re.search(p, line, re.I) for p in patterns)]
    return selected or _lines(output, 12)


def _nikto(output: str) -> list[str]:
    ignored = re.compile(r"^(?:- Nikto|Target IP:|Target Hostname:|Start Time:|End Time:|\+ \d+ requests:)", re.I)
    selected = [line for line in _lines(output, 300) if line.startswith("+") and not ignored.search(line)]
    return selected or [line for line in _lines(output, 20) if not ignored.search(line)]


def _nuclei(output: str) -> list[str]:
    selected = []
    for line in _lines(output, 500):
        if line.startswith("{"):
            try:
                item = json.loads(line)
                info = item.get("info") or {}
                selected.append(" | ".join(str(v) for v in (
                    item.get("template-id"), info.get("severity"), item.get("matched-at") or item.get("host")
                ) if v))
                continue
            except ValueError:
                pass
        if re.search(r"\[(?:critical|high|medium|low|info|unknown)\]", line, re.I):
            selected.append(line)
    return selected or [line for line in _lines(output, 20) if not re.search(r"\b(?:INF|WRN)\b|templates? loaded|requests? sent", line, re.I)]


def _sqlmap(output: str) -> list[str]:
    keep = re.compile(r"injectable|parameter:|type:|title:|payload:|back-end DBMS|web application technology|identified the following injection|not injectable|all tested parameters|critical|warning", re.I)
    return [line for line in _lines(output, 300) if keep.search(line)] or _lines(output, 15)


def _headers(output: str) -> list[str]:
    allowed = re.compile(r"^(?:HTTP/|location:|server:|content-type:|content-length:|set-cookie:|strict-transport-security:|content-security-policy:|x-frame-options:|x-content-type-options:|access-control-allow-origin:)", re.I)
    return [line for line in _lines(output, 200) if allowed.search(line)] or _lines(output, 12)


def _zap(output: str) -> list[str]:
    values = _headers(output)
    values.extend(line for line in _lines(output, 100) if re.match(r"[1-5]\d\d\s+\S+", line))
    return list(dict.fromkeys(values))


def compact_tool_output(tool_name: str, args: dict, text: object) -> str:
    """Compress one invocation without allowing the LLM to invent a summary."""
    data = _payload(text)
    output = _text(data)
    if tool_name == "ping_target":
        return _ping(data, output)
    if tool_name == "nmap_scan":
        return _nmap(data, output)
    if tool_name == "dns_recon":
        records = _marked_sections(output)
    elif tool_name == "ssl_check":
        records = _tls(output)
    elif tool_name == "whois_lookup":
        records = _whois(output)
    elif tool_name == "nikto_scan":
        records = _nikto(output)
    elif tool_name == "nuclei_scan":
        records = _nuclei(output)
    elif tool_name == "subfinder_enum":
        records = sorted(set(_lines(output, 500)))
    elif tool_name == "traceroute_target":
        records = _lines(output, 40)
    elif tool_name == "curl_headers":
        records = _headers(output)
    elif tool_name == "sqlmap_scan":
        records = _sqlmap(output)
    elif tool_name == "zap_scan":
        records = _zap(output)
    elif tool_name == "zeek_analyze":
        records = _lines(output, 80)
    elif tool_name in {"get_local_ip", "get_local_network", "scanner_tool_health"}:
        values = {key: value for key, value in data.items() if key not in {"output", "stderr"}}
        return json.dumps(values, ensure_ascii=False, separators=(",", ":"))
    else:
        records = _lines(output, 40)
    if not records:
        records = [str(data.get("error") or data.get("status") or "no findings")]
    prefix = f"status={_status(data)}"
    return _bounded([prefix, *records], len(records) + 1)


def _collapse_ips(labels: list[str]) -> str:
    unique = []
    for label in labels:
        try:
            unique.append(ipaddress.ip_address(label))
        except ValueError:
            return ",".join(labels)
    if not unique or len({ip.version for ip in unique}) != 1:
        return ",".join(labels)
    values, groups = sorted(set(int(ip) for ip in unique)), []
    start = previous = values[0]
    for value in values[1:]:
        if value == previous + 1:
            previous = value
            continue
        groups.append((start, previous))
        start = previous = value
    groups.append((start, previous))
    version = unique[0].version
    result = []
    for left, right in groups:
        first = str(ipaddress.ip_address(left))
        if left == right:
            result.append(first)
        else:
            last = str(ipaddress.ip_address(right))
            result.append(f"{first}-{last}")
    return ",".join(result)


def compact_tool_sections(tool_name: str, sections: list[tuple[str | None, str]], budget: int = DEFAULT_BUDGET) -> str:
    """Merge hosts, group duplicate outcomes, and truncate only at record boundaries."""
    header = f"[COMPRESSED tool={tool_name} total={len(sections)} complete={len(sections)}]"
    groups: dict[str, list[str]] = defaultdict(list)
    unlabeled = []
    for label, result in sections:
        if label:
            groups[result].append(label)
        else:
            unlabeled.append(result)
    records = []
    if tool_name == "ping_target" and groups:
        states: dict[str, list[str]] = defaultdict(list)
        detail = []
        for result, labels in groups.items():
            state = result.split(maxsplit=1)[0]
            states[state].extend(labels)
            if state == "UP" and len(result.split()) > 1:
                detail.extend(f"{label} {' '.join(result.split()[1:])}" for label in labels)
        for state in ("UP", "DOWN", "ERROR"):
            if states[state]:
                records.append(f"{state}({len(states[state])}): {_collapse_ips(states[state])}")
        if detail:
            records.append("UP_DETAILS: " + "; ".join(detail))
    else:
        for result, labels in groups.items():
            records.append(f"{_collapse_ips(labels)} | {result}")
    records.extend(unlabeled)
    output, used, kept = [header], len(header) + 1, 0
    for record in records:
        if len(record) > MAX_ITEM_CHARS:
            record = record[:MAX_ITEM_CHARS] + " [FIELD_TRUNCATED]"
        if used + len(record) + 1 > budget:
            break
        output.append(record)
        used += len(record) + 1
        kept += 1
    omitted = len(records) - kept
    if omitted:
        output.append(f"[COMPRESSED_BUDGET: {omitted} complete records omitted; scan execution count remains {len(sections)}]")
    return "\n".join(output)
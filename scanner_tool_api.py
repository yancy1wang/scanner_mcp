"""Scanner Tool node: executes authorized network scans locally."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shlex
import subprocess
import time
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, ValidationError
from local_network import detect_local_configuration

app = FastAPI(title="Scanner Tool")

CONTAINER = os.getenv("SANDBOX_CONTAINER", "scanner-mcp-test")
MAX_PREFIX = int(os.getenv("MAX_NETWORK_PREFIX", "24"))
ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(value.strip())
    for value in os.getenv(
        "ALLOWED_NETWORKS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    ).split(",")
    if value.strip()
)


PORTS_PATTERN = r"^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*$"


class ScanRequest(BaseModel):
    target: str = Field(description="Authorized IPv4 or IPv6 CIDR network")
    ports: str = Field(
        default="1-65535",
        pattern=PORTS_PATTERN,
        description="Single port, range, or comma-separated mix, e.g. 22,80,443,8000-8100",
    )


def _authorized_network(target: str) -> ipaddress._BaseNetwork:
    """确认扫描的目标网络是否合法"""
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="target must be a valid CIDR network") from exc

    if network.prefixlen < MAX_PREFIX:
        raise HTTPException(
            status_code=400,
            detail=f"network must be /{MAX_PREFIX} or smaller in size",
        )
    if not any(network.subnet_of(allowed) for allowed in ALLOWED_NETWORKS):
        raise HTTPException(status_code=403, detail="target network is not authorized")
    return network


def _authorized_ports(ports: str) -> str:
    if not re.fullmatch(PORTS_PATTERN, ports):
        raise HTTPException(status_code=400, detail="ports must be comma-separated ports or ranges, e.g. 22,80,8000-8100")
    normalized = []
    for item in ports.split(","):
        parts = item.split("-")
        start = int(parts[0])
        end = int(parts[-1])
        if not 1 <= start <= end <= 65535:
            raise HTTPException(status_code=400, detail="each port range must be ascending and within 1-65535")
        normalized.append(f"{start}-{end}" if start != end else str(start))
    return ",".join(normalized)


async def _run_nmap(target: str, ports: str) -> dict[str, Any]:
    command = [
        "docker", "exec", CONTAINER,
        "nmap", "-n", "-Pn", "--open", "-p", ports, target,
    ]
    started = time.monotonic()
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=900)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return {"success": False, "status": "timeout", "error": "scan timed out after 900 seconds"}
    except FileNotFoundError:
        return {"success": False, "status": "error", "error": "Docker CLI is not available"}

    output = stdout.decode("utf-8", errors="replace")[:100000]
    error = stderr.decode("utf-8", errors="replace")[:10000]
    return {
        "success": process.returncode == 0,
        "status": "completed" if process.returncode == 0 else "failed",
        "target": target,
        "ports": ports,
        "output": output,
        "error": error,
        "exit_code": process.returncode,
        "duration": round(time.monotonic() - started, 2),
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "scanner-tool"}


async def scan_network(
    request: ScanRequest,
) -> dict[str, Any]:
    network = _authorized_network(request.target)
    ports = _authorized_ports(request.ports)
    return await _run_nmap(str(network), ports)


class ToolRequest(BaseModel):
    args: dict[str, Any] = Field(default_factory=dict)


def _safe_value(value: Any, name: str) -> str:
    text = str(value).strip()
    if not text or len(text) > 500 or not re.fullmatch(r"[A-Za-z0-9._:/?=&%+,-]+", text):
        raise HTTPException(status_code=400, detail=f"invalid {name}")
    return text


async def _run_tool_command(command: str, timeout: int = 120) -> dict[str, Any]:
    process_args = ["docker", "exec", CONTAINER, "bash", "-lc", command]
    started = time.monotonic()
    try:
        process = await asyncio.create_subprocess_exec(
            *process_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return {"success": False, "status": "timeout", "error": f"timed out after {timeout}s"}
    except FileNotFoundError:
        return {"success": False, "status": "error", "error": "Docker CLI is not available"}

    output = stdout.decode("utf-8", errors="replace")[:100000]
    error = stderr.decode("utf-8", errors="replace")[:10000]
    return {
        "success": process.returncode == 0,
        "status": "completed" if process.returncode == 0 else "failed",
        "output": output or error,
        "stderr": error,
        "exit_code": process.returncode,
        "duration": round(time.monotonic() - started, 2),
    }


async def _run_tool(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    if tool_name in {"get_local_ip", "get_local_network"}:
        try:
            config = await asyncio.to_thread(detect_local_configuration)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            return {"success": False, "status": "error", "error": str(exc)}
        return {
            "success": True,
            "status": "completed",
            "source": "scanner_tool_host",
            **config,
        }
    if tool_name == "nmap_scan":
        try:
            scan_request = ScanRequest(**args)
        except ValidationError as exc:
            raise RequestValidationError(exc.errors()) from exc
        return await scan_network(scan_request)

    target = _safe_value(args.get("target") or args.get("domain") or args.get("url"), "target")
    quoted = shlex.quote(target)
    commands: dict[str, tuple[str, int]] = {
        "dns_recon": (
            " && ".join([
                f"echo '=== DNS Records ==='; dig {quoted} ANY +short",
                f"echo '=== MX Records ==='; dig {quoted} MX +short",
                f"echo '=== NS Records ==='; dig {quoted} NS +short",
                f"echo '=== TXT Records ==='; dig {quoted} TXT +short",
                f"echo '=== DMARC ==='; dig {shlex.quote('_dmarc.' + target)} TXT +short",
            ]), 60,
        ),
        "whois_lookup": (f"whois {quoted} 2>&1 | head -80", 30),
        "subfinder_enum": (f"subfinder -d {quoted} -silent 2>&1 | head -50", 60),
        "traceroute_target": (f"traceroute -m 15 {quoted} 2>&1", 60),
        "ping_target": (f"ping -c {int(args.get('count', 4))} {quoted} 2>&1", 30),
        "nikto_scan": (f"nikto -h {quoted} -maxtime 120 2>&1", 180),
        "nuclei_scan": (
            f"nuclei -u {quoted} -severity critical,high -stats -timeout 10 2>&1", 300
        ),
        "sqlmap_scan": (
            f"sqlmap -u {quoted} --batch --level=1 --risk=1 --timeout=30 --retries=1 2>&1 | tail -80", 120
        ),
        "curl_headers": (f"curl -sI -L --max-time 10 {quoted} 2>&1", 15),
    }
    if tool_name == "ssl_check":
        host, _, port = target.partition(":")
        port = port or "443"
        command = f"echo | openssl s_client -connect {shlex.quote(host + ':' + port)} -servername {shlex.quote(host)} 2>/dev/null | openssl x509 -noout -text -dates -subject -issuer 2>&1"
        return await _run_tool_command(command, 30)
    if tool_name == "nuclei_scan" and args.get("templates"):
        templates = _safe_value(args["templates"], "templates")
        commands[tool_name] = (f"nuclei -u {quoted} -t {shlex.quote(templates)} -stats -timeout 10 2>&1", 300)
    if tool_name == "zap_scan":
        command = f"curl -sI --max-time 10 {quoted} 2>&1; echo '=== common paths ==='; for path in robots.txt .env .git/config admin login; do curl -sI --max-time 5 -o /dev/null -w '%{{http_code}} $path\\n' {quoted}/$path; done"
        return await _run_tool_command(command, 90)
    if tool_name == "zeek_analyze":
        command = f"command -v zeek >/dev/null && zeek -r {quoted} 2>&1 || tcpdump -nn -r {quoted} 2>&1 | head -60"
        return await _run_tool_command(command, 60)
    command, timeout = commands.get(tool_name, ("", 0))
    if not command:
        raise HTTPException(status_code=404, detail=f"unknown scanner tool: {tool_name}")
    return await _run_tool_command(command, timeout)


SUPPORTED_TOOLS = {
    "nmap_scan",
    "dns_recon", "ssl_check", "whois_lookup", "nikto_scan", "nuclei_scan",
    "subfinder_enum", "traceroute_target", "ping_target", "curl_headers",
    "sqlmap_scan", "zeek_analyze", "zap_scan",
    "get_local_ip", "get_local_network",
}


@app.post("/tools/{tool_name}")
async def run_tool(
    tool_name: str,
    request: ToolRequest,
) -> dict[str, Any]:
    if tool_name not in SUPPORTED_TOOLS:
        raise HTTPException(status_code=404, detail=f"unknown scanner tool: {tool_name}")
    return await _run_tool(tool_name, request.args)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.getenv("SCANNER_TOOL_HOST", "0.0.0.0"),
        port=int(os.getenv("SCANNER_TOOL_PORT", "9001")),
    )

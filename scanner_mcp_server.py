"""MCP control node: forwards authorized scan requests to Scanner Tool."""

from __future__ import annotations

import os

import httpx
from mcp.server.fastmcp import FastMCP


SCANNER_TOOL_URL = os.getenv("SCANNER_TOOL_URL", "http://192.168.88.233:9001")
HTTP_TIMEOUT = float(os.getenv("SCANNER_TOOL_TIMEOUT", "930"))

mcp = FastMCP(
    "scanner-control",
    host=os.getenv("MCP_SERVER_HOST", "0.0.0.0"),
    port=int(os.getenv("MCP_SERVER_PORT", "8001")),
    streamable_http_path="/mcp",
)


@mcp.tool()
async def scanner_tool_health() -> dict:
    """检查mcp server和tool的连接状态"""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{SCANNER_TOOL_URL.rstrip('/')}/health")
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as exc:
        return {"status": "disconnected", "error": str(exc)}


async def _call_tool(tool_name: str, args: dict) -> dict:
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            response = await client.post(
                f"{SCANNER_TOOL_URL.rstrip('/')}/tools/{tool_name}",
                json={"args": args},
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        return {"success": False, "status": "rejected", "error": exc.response.text[:8000]}
    except httpx.HTTPError as exc:
        return {"success": False, "status": "unavailable", "error": str(exc)}



@mcp.tool()
async def nmap_scan(
    target: str,
    ports: str = "1-65535",
) -> dict:
    """Run an Nmap port scan on an authorized target or CIDR network.

    ports accepts a single port, a range, or a comma-separated mix such as
    "22,80,443,8000-8100". Ports must be 1-65535 and ranges must be ascending.
    """
    return await _call_tool("nmap_scan", {"target": target, "ports": ports})


@mcp.tool()
async def dns_recon(domain: str) -> dict:
    """Run DNS reconnaissance on a domain."""
    return await _call_tool("dns_recon", {"domain": domain})


@mcp.tool()
async def ssl_check(target: str) -> dict:
    """Check SSL/TLS configuration for an authorized IP, host, or CIDR.

    Pass an explicitly supplied target through unchanged. The client expands a
    CIDR containing at most 256 usable addresses into individual host calls.
    Do not query the local network or reject CIDR input.
    """
    return await _call_tool("ssl_check", {"target": target})


@mcp.tool()
async def whois_lookup(target: str) -> dict:
    """Run WHOIS lookup on an authorized domain, IP, or CIDR.

    Pass an explicitly supplied target through unchanged. The client expands a
    CIDR containing at most 256 usable addresses into individual host calls.
    Do not query the local network or reject CIDR input.
    """
    return await _call_tool("whois_lookup", {"target": target})


@mcp.tool()
async def nikto_scan(target: str) -> dict:
    """Run Nikto on an authorized IP, host, or CIDR.

    Pass an explicitly supplied target through unchanged. The client expands a
    CIDR containing at most 256 usable addresses into individual host calls.
    Do not query the local network or reject CIDR input.
    """
    return await _call_tool("nikto_scan", {"target": target})


@mcp.tool()
async def nuclei_scan(target: str, templates: str = "") -> dict:
    """Run Nuclei on an authorized IP, host, or CIDR.

    Pass an explicitly supplied target through unchanged. The client expands a
    CIDR containing at most 256 usable addresses into individual host calls.
    Do not query the local network or reject CIDR input.
    """
    return await _call_tool("nuclei_scan", {"target": target, "templates": templates})


@mcp.tool()
async def subfinder_enum(domain: str) -> dict:
    """Enumerate subdomains using subfinder."""
    return await _call_tool("subfinder_enum", {"domain": domain})


@mcp.tool()
async def traceroute_target(target: str) -> dict:
    """Run traceroute to an authorized IP, host, or CIDR.

    Pass an explicitly supplied target through unchanged. The client expands a
    CIDR containing at most 256 usable addresses into individual host calls.
    Do not query the local network or reject CIDR input.
    """
    return await _call_tool("traceroute_target", {"target": target})


@mcp.tool()
async def ping_target(target: str, count: int = 4) -> dict:
    """Ping an authorized IP address or CIDR network.

    Always pass an explicitly supplied target through unchanged. Although the
    backend command handles one host at a time, the client accepts CIDR targets
    (for example, 192.168.88.0/30 or 192.168.88.0/24) and expands up to 256
    usable addresses into individual calls. Do not call get_local_network when
    the user already supplied an IP or CIDR, and do not reject CIDR input.
    """
    return await _call_tool("ping_target", {"target": target, "count": count})


@mcp.tool()
async def curl_headers(url: str) -> dict:
    """Fetch HTTP headers from an authorized URL, IP, host, or CIDR.

    Put an explicitly supplied CIDR in the url argument unchanged. The client
    expands a CIDR containing at most 256 usable addresses and adds http:// to
    each host. Do not query the local network or reject CIDR input.
    """
    return await _call_tool("curl_headers", {"url": url})


@mcp.tool()
async def sqlmap_scan(url: str) -> dict:
    """Run sqlmap on an authorized URL, IP, host, or CIDR.

    Put an explicitly supplied CIDR in the url argument unchanged. The client
    expands a CIDR containing at most 256 usable addresses and adds http:// to
    each host. Do not query the local network or reject CIDR input.
    """
    return await _call_tool("sqlmap_scan", {"url": url})


@mcp.tool()
async def zeek_analyze(target: str) -> dict:
    """Analyze a PCAP file or capture traffic with Zeek/tcpdump."""
    return await _call_tool("zeek_analyze", {"target": target})


@mcp.tool()
async def zap_scan(target: str) -> dict:
    """Run an OWASP ZAP baseline check on an authorized host or CIDR.

    Pass an explicitly supplied target through unchanged. The client expands a
    CIDR containing at most 256 usable addresses into individual host calls.
    Do not query the local network or reject CIDR input.
    """
    return await _call_tool("zap_scan", {"target": target})

@mcp.tool()
async def get_local_ip() -> dict:
    """Get the Scanner Tool host's real LAN IPv4 address (本机 IP/本机的IP地址).

    Prefer physical interface enp4s0; exclude Docker, virtual and loopback
    interfaces. Call this to resolve a local-host target before scanning it.
    Returns ipv4, interface, network and source; no URL or target is needed.
    Never infer the host IP from traceroute or the Docker gateway.
    """
    return await _call_tool("get_local_ip", {})

@mcp.tool()
async def get_local_network() -> dict:
    """Get the Scanner Tool host's LAN CIDR (本机网段/当前网段/本网段).

    Read the physical interface's IPv4 and actual prefix length, preferring
    enp4s0 and excluding Docker/virtual interfaces. Call before scanning the
    local subnet, then use the returned network as the scan target.
    Returns network, ipv4, interface and source; no URL or target is needed.
    """
    return await _call_tool("get_local_network", {})



if __name__ == "__main__":
    mcp.run(transport="streamable-http")

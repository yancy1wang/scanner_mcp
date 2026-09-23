# Scanner command container used by scanner_tool_api.py via docker exec.
# Build: docker build -t scanner-tools:local .
# Run: docker run -d --init --name scanner-mcp-test scanner-tools:local
FROM kalilinux/kali-rolling:latest

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        curl \
        dnsutils \
        iputils-ping \
        nikto \
        nmap \
        nuclei \
        openssl \
        sqlmap \
        subfinder \
        tcpdump \
        traceroute \
        whois \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Download templates at build time, before the first Nuclei scan.
RUN nuclei -update-templates

# Fail the build if a command required by the backend is missing.
RUN bash -lc 'set -e; for tool in bash curl dig ping nikto nmap nuclei openssl sqlmap subfinder tcpdump traceroute whois head tail; do command -v "$tool"; done'

# zeek_analyze uses the backend's existing tcpdump fallback.
# zap_scan currently uses curl; the backend does not invoke ZAP.
WORKDIR /workspace

# Keep the container available for docker exec; Python services run on the host.
CMD ["sleep", "infinity"]

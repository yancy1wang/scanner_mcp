import argparse
import asyncio
import json
import os
import re
import sys
import time
import traceback
from typing import Dict, List
from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from langchain_openai import ChatOpenAI
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from output_compaction import compact_tool_output, compact_tool_sections
from client_defaults import (
    COMMON_PORTS,
    MAX_HOSTS,
    NETWORK_TOOL,
    clean_network_note,
    expand_host_calls,
    extract_live_hosts,
    is_ip,
    narrow_to_prefix,
    network_hosts,
    normalize_ports,
    prepare_tool_call,
    server_host_from_url,
    with_host,
)

load_dotenv()

# logging.basicConfig(level=logging.DEBUG)

 # logging.getLogger("mcp").setLevel(logging.DEBUG)


def read_query() -> str:
    """Read a complete UTF-8 line without input()'s terminal editing path."""
    print("\nQuery: ", end="", flush=True)
    raw = sys.stdin.buffer.readline()
    if not raw:
        raise EOFError
    # Decode only after consuming the line, so invalid input is never executed
    # and the next prompt can accept a fresh line without residual bytes.
    return raw.decode("utf-8", errors="strict").strip()


def sanitize_query(text: str) -> str:
    """删除输入中的非法UTF-16代理字符"""
    return "".join(
        char for char in text
        if not 0xD800 <= ord(char) <= 0xDFFF
    )



class Monitor(BaseCallbackHandler):
    def on_llm_start(self, serialized, prompts, **kwargs):
        print(f"\n🔁 [LLM调用] 提示(前200): {str(prompts)[:200]}...")
    def on_llm_end(self, response, **kwargs):
        if hasattr(response, 'generations') and response.generations:
            gen = response.generations[0][0]
            content = gen.message.content if hasattr(gen.message, 'content') else str(gen)
            print(f"   LLM返回(前2000): {content[:2000]}")

deepseek_key = os.getenv("DEEPSEEK_API_KEY")
deepseek_base = "https://api.deepseek.com/v1"
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://192.168.88.233:8001/mcp")

HOSTS_CACHE_TTL = 300.0  #本网段内存活主机列表缓存时间
HEALTH_CACHE_TTL = 60.0 #执行段健康检查结果缓存时间
SYSTEM_PROMPT = (
    "你是授权网络扫描助手。用户查询或扫描本机 IP 时，先调用 get_local_ip；"
    "如果用户指令中含有明确的工具名，必须严格按照其意图选择并调用该工具，不得遗漏、替换或擅自改用其他工具。"
    "查询或扫描当前网段时，先调用 get_local_network，再使用返回的 ipv4 或 network。"
    "这两个工具读取 Scanner Tool 执行节点宿主机的物理网卡，优先 enp4s0，"
    "不是客户端机器、Docker 容器或 MCP 控制节点的地址。"
    "不要根据 traceroute、ping、Docker 网关或服务器 URL 猜测本机 IP、网段。"
    "只查询地址时，报告工具返回的值即可，不要发起扫描。"
    "工具失败时报告原因并请求明确的目标；扫描被拒绝时不要换网段或拆分绕过限制。"
    "用户已经明确提供 IP、域名、通配符、地址范围或 CIDR 时，必须直接使用该目标，"
    "不要调用 get_local_ip 或 get_local_network 进行确认、替换或再次请求授权。"
    "ping_target 等单主机工具可以接收 CIDR；客户端会在最多 256 个可用地址的安全上限内"
    "自动展开并逐台调用。因此对于 /30、/24 等不超过上限的 CIDR，必须把原 CIDR 原样传给工具，"
    "不要声称工具不支持 CIDR，也不要改用 nmap_scan。"
    "当用户明确要求执行检查或扫描、但未给目标时，默认目标是 Scanner Tool 宿主机："
    "先调用 get_local_ip，再用返回的 ipv4 执行所请求的工具，不要只追问目标。"
)

_TARGETLESS_TOOL_PATTERNS = (
    (re.compile(r"(?:ssl|tls|证书)", re.I), "ssl_check"),
    (re.compile(r"(?:\bping\b|连通性?)", re.I), "ping_target"),
    (re.compile(r"(?:traceroute|路由追踪|路由跟踪)", re.I), "traceroute_target"),
    (re.compile(r"(?:http.*(?:头|header)|(?:头|header).*http|curl)", re.I), "curl_headers"),
    (re.compile(r"(?:whois|域名信息)", re.I), "whois_lookup"),
    (re.compile(r"(?:端口扫描|扫描端口|\bnmap\b)", re.I), NETWORK_TOOL),
)
_EXECUTION_REQUEST_PATTERN = re.compile(
    r"(?:检查|检测|扫描|探测|查询|查一下|查下|查看|执行|\b(?:check|scan|ping|traceroute|curl|whois|nmap)\b)",
    re.I,
)


class DefaultsUnavailable(Exception):
    """所有兜底来源都拿不到必需参数时抛出，工具调用会被安全跳过。"""


def _result_text(result) -> str:
    """把 MCP 工具返回的内容统一成文本。"""
    content = result.content if hasattr(result, "content") else result
    if isinstance(content, list) and content and hasattr(content[0], "text"):
        return "\n".join(chunk.text for chunk in content if hasattr(chunk, "text"))
    return str(content)




class ScannerBot:
    def __init__(self, default_network: str | None = None, default_ports: str = COMMON_PORTS):
        self.sessions: Dict[str, ClientSession] = {}
        self.tool_to_server: Dict[str, str] = {}
        self.available_tools: List[dict] = []
        self.llm_with_tools = None
        self.llm = None

        # 容错配置：默认端口 / 默认网段（--target、DEFAULT_NETWORK 可覆盖）
        self.default_ports = default_ports
        self.server_host = server_host_from_url(MCP_SERVER_URL)
        self.network: str | None = default_network
        self.network_source = "override" if default_network else "none"
        self._hosts_cache: Dict[str, tuple] = {}
        self._health_checked_at = 0.0
        self._scanner_ok = True
        self._connected = False

    def _network_label(self) -> str:
        return {
            "tool": "工具确认的宿主机网段",
            "override": "配置的默认网段",
        }.get(self.network_source, "默认网段")

    def _remember_local_network(self, result):
        if self.network_source == "override":
            return
        data = getattr(result, "structuredContent", None)
        if not isinstance(data, dict):
            try:
                data = json.loads(_result_text(result))
            except (TypeError, ValueError):
                return
        if not isinstance(data, dict) or data.get("success") is not True:
            return
        network, _ = clean_network_note(data.get("network"))
        if network:
            self.network, self.network_source = network, "tool"

    @staticmethod
    def _result_data(result) -> dict | None:
        data = getattr(result, "structuredContent", None)
        if isinstance(data, dict):
            return data
        try:
            data = json.loads(_result_text(result))
        except (TypeError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    async def _local_ip(self, notes: List[str]) -> str:
        session = self.sessions.get("security")
        if not session or "get_local_ip" not in self.tool_to_server:
            raise DefaultsUnavailable("get_local_ip 工具不可用，无法补全默认本机目标")
        result = await self._call_tool(session, "get_local_ip", {})
        data = self._result_data(result)
        ipv4 = data.get("ipv4") if data and data.get("success") is True else None
        if not isinstance(ipv4, str) or not is_ip(ipv4):
            detail = data.get("error") if data else _result_text(result)
            raise DefaultsUnavailable(f"获取默认本机 IP 失败：{detail}")
        notes.append(f"未指定目标，使用 get_local_ip 返回的本机 IP {ipv4}")
        return ipv4

    @staticmethod
    def _targetless_tool(query: str) -> str | None:
        if not _EXECUTION_REQUEST_PATTERN.search(query):
            return None
        for pattern, tool_name in _TARGETLESS_TOOL_PATTERNS:
            if pattern.search(query):
                return tool_name
        return None

    async def _fallback_targetless_request(self, query: str) -> str | None:
        tool_name = self._targetless_tool(query)
        if tool_name is None or tool_name not in self.tool_to_server:
            return None
        notes: List[str] = []
        try:
            ipv4 = await self._local_ip(notes)
            if tool_name == NETWORK_TOOL:
                args = {"target": ipv4, "ports": self.default_ports}
            else:
                _, args = with_host(tool_name, {}, ipv4)
            session = self.sessions["security"]
            result = await self._call_tool(session, tool_name, args)
            return "\n".join([*notes, f"兜底调用 {tool_name}({args}) 的结果：", _result_text(result)])
        except DefaultsUnavailable as exc:
            return f"目标缺失兜底失败：{exc}"

    async def _live_hosts(self) -> List[str]:
        """发现默认网段内的存活主机：优先 host_discovery，其次 nmap 常见端口扫描。"""
        network = self.network
        if not network:
            return []
        cached = self._hosts_cache.get(network)
        if cached and time.monotonic() - cached[0] < HOSTS_CACHE_TTL:
            return cached[1]
        hosts: List[str] = []
        session = self.sessions.get("security")
        if session:
            print(f"\n🔎 未指定目标 IP，正在发现 {network} 内的存活主机...")
            try:
                if not await self._scanner_ready():
                    print("   ⚠️ 后端不可用，跳过存活主机发现")
                    return []
                if "host_discovery" in self.tool_to_server:
                    result = await self._call_tool(session, "host_discovery", {"target": network})
                    hosts = extract_live_hosts(_result_text(result))
                if not hosts:
                    result = await self._call_tool(
                        session, NETWORK_TOOL, {"target": network, "ports": self.default_ports}
                    )
                    hosts = extract_live_hosts(_result_text(result))
            except Exception as exc:
                print(f"   ⚠️ 存活主机发现失败：{exc}")
            if hosts:
                preview = ", ".join(hosts[:MAX_HOSTS])
                suffix = " ..." if len(hosts) > MAX_HOSTS else ""
                print(f"   发现 {len(hosts)} 台存活主机：{preview}{suffix}")
            else:
                print("   未发现响应端口探测的存活主机。")
        self._hosts_cache[network] = (time.monotonic(), hosts)
        return hosts

    async def _host_calls(self, tool_name: str, prepared: dict, pending: str, notes: List[str]):
        """把缺失的主机/域名参数补成可用值，返回 (label, args) 调用列表。"""
        if pending == "hostname":
            if self.server_host and not is_ip(self.server_host):
                notes.append(f"未指定域名，使用服务器域名 {self.server_host}")
                return [with_host(tool_name, prepared, self.server_host)], notes
            raise DefaultsUnavailable(f"{tool_name} 缺少域名参数，无法自动推断，请明确提供域名")
        ipv4 = await self._local_ip(notes)
        return [with_host(tool_name, prepared, ipv4)], notes

    def _network_host_calls(self, tool_name: str, prepared: dict, notes: List[str]):
        """Expand an explicit CIDR supplied to a single-host tool."""
        network = prepared.pop("_target_network")
        try:
            hosts = network_hosts(network)
        except ValueError as exc:
            raise DefaultsUnavailable(
                f"无法展开网段 {network}：{exc}。请缩小网段后重试"
            ) from exc
        notes.append(
            f"工具 {tool_name} 仅接受单主机，已将网段 {network} 展开为 {len(hosts)} 次调用"
        )
        if not hosts:
            raise DefaultsUnavailable(f"网段 {network} 没有可用主机地址")
        return expand_host_calls(tool_name, prepared, hosts), notes

    async def _call_tool(self, session: ClientSession, tool_name: str, args: dict, attempts: int = 2):
        """调用工具，对传输层失败做退避重试。"""
        delay = 1.0
        for attempt in range(1, attempts + 1):
            try:
                return await session.call_tool(tool_name, args)
            except Exception as exc:
                if attempt == attempts:
                    raise
                print(f"   ↻ 调用 {tool_name} 失败（{exc}），{delay:.0f}s 后重试")
                await asyncio.sleep(delay)
                delay *= 2

    async def _scanner_ready(self) -> bool:
        """扫描类工具调用前检查后端可用性，避免发起必然失败的长扫描。"""
        now = time.monotonic()
        if now - self._health_checked_at < HEALTH_CACHE_TTL:
            return self._scanner_ok
        ok = True
        session = self.sessions.get("security")
        if session and "scanner_tool_health" in self.tool_to_server:
            try:
                text = _result_text(await self._call_tool(session, "scanner_tool_health", {}))
                ok = '"ok"' in text
            except Exception:
                ok = True
        self._health_checked_at, self._scanner_ok = now, ok
        return ok

    async def process_query(self, query: str):
        clean_query = sanitize_query(query)
        if clean_query != query:
            print("\n⚠️ 检测到终端输入中的无效Unicode字符，已自动清理。")
        query = clean_query

        messages: List = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=query)]
        max_iterations = 10
        fallback_used = False
        tool_call_seen = False
        for _ in range(max_iterations):
            response: AIMessage = await self.llm_with_tools.ainvoke(messages)
            messages.append(response)
            if not response.tool_calls:
                # The targetless fallback is only for cases where the model never
                # called a tool.  After a successful tool round, a tool-less
                # response is the final answer and must not trigger a second call
                # against the local host.
                if not tool_call_seen and not fallback_used:
                    fallback_used = True
                    fallback = await self._fallback_targetless_request(query)
                    if fallback:
                        messages.append(HumanMessage(content=fallback + "\n请根据上述结果回答用户。"))
                        continue
                break
            tool_call_seen = True
            for tool_call in response.tool_calls:
                tool_name = tool_call.get("name")
                tool_args = tool_call.get("args", {})
                tool_call_id = tool_call.get("id")
                
                # 根据工具名找到对应的服务会话
                server_name = self.tool_to_server.get(tool_name)
                session = self.sessions.get(server_name)
                
                print(f"\n🔧 [调用工具] {tool_name}({json.dumps(tool_args, ensure_ascii=False)[:200]}) 来自服务: {server_name}")
                try:
                    prepared, notes, pending = prepare_tool_call(tool_name, tool_args)
                    calls: List[tuple] = [(None, prepared)]
                    if pending == "network":
                        prepared["target"] = await self._local_ip(notes)
                    elif pending == "host_network":
                        calls, notes = self._network_host_calls(tool_name, prepared, notes)
                    elif pending in {"host", "hostname"}:
                        calls, notes = await self._host_calls(tool_name, prepared, pending, notes)
                    for note in notes:
                        print(f"   ⚠️ {note}")
                    if not session:
                        raise RuntimeError(f"未找到处理工具 {tool_name} 的服务会话")
                    sections: List[tuple[str | None, str]] = []
                    for label, call_args in calls:
                        if label:
                            print(f"   → {label}: {json.dumps(call_args, ensure_ascii=False)[:160]}")
                        if tool_name == NETWORK_TOOL and not await self._scanner_ready():
                            message = "Scanner tool 当前不可达，本次扫描未发起，请检查服务端 /health。"
                            sections.append((label, message))
                            break
                        try:
                            result = await self._call_tool(session, tool_name, call_args)
                            if tool_name == "get_local_network":
                                self._remember_local_network(result)
                            text = compact_tool_output(tool_name, call_args, _result_text(result))
                        except Exception as exc:
                            text = compact_tool_output(tool_name, call_args, json.dumps({"success": False, "status": "error", "error": f"Tool call error: {exc}"}))
                        sections.append((label, text))
                    tool_content = compact_tool_sections(tool_name, sections) if sections else "Tool call produced no output"
                except DefaultsUnavailable as e:
                    tool_content = f"Tool call skipped: {e}（请提示用户补充该参数）"
                except Exception as e:
                    tool_content = f"Tool call error: {str(e)}"
                messages.append(ToolMessage(content=str(tool_content), tool_call_id=tool_call_id))
        final_answer = messages[-1].content if isinstance(messages[-1], AIMessage) else str(messages[-1])
        print(f"\n💬 回答:\n{final_answer}")
        return final_answer


    async def run_chat(self): 
        """运行聊天循环"""
        print("\nMCP Chatbot Started!")
        print("Type your queries or 'quit' / 'exit' to exit.")
        
        while True:
            try:
                query = read_query()
            except EOFError:
                break
            except UnicodeDecodeError:
                print(
                    "\n终端输入不是完整有效的 UTF-8，本次输入未提交。"
                    "请确认 SSH 终端使用 UTF-8，并重新粘贴完整的一行文字。"
                )
                traceback.print_exc()
                continue
            try:
        
                if query.strip().lower() in {"quit", "exit"}:
                    break
                if not query:
                    continue
                    
                await self.process_query(query)
                print("\n")
                    
            except Exception as e:
                print(f"\nError: {str(e)}")
                traceback.print_exc()


    async def connect_to_server_and_run(self, prompt: str | None = None):
        attempts = 3
        for attempt in range(1, attempts + 1):
            try:
                await self._serve(prompt)
                return
            except Exception as exc:
                if self._connected or attempt == attempts:
                    raise
                delay = 2 ** attempt
                print(f"\n⚠️ 连接 MCP 服务失败（{exc}），{delay}s 后重试（{attempt}/{attempts}）")
                await asyncio.sleep(delay)

    async def _serve(self, prompt: str | None = None):
        self.sessions.clear()
        self.tool_to_server.clear()
        self.available_tools.clear()
        self._connected = False
        async with streamable_http_client(MCP_SERVER_URL) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                self._connected = True
                self.sessions["security"] = session

                response = await session.list_tools()
                print("\nConnected to MCP server with tools:", [tool.name for tool in response.tools])

                for tool in response.tools:
                    self.tool_to_server[tool.name] = "security"
                    self.available_tools.append({
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": tool.description or "",
                            "parameters": tool.inputSchema,
                        },
                    })

                llm = ChatOpenAI(
                    model="deepseek-v4-flash",
                    temperature=0.3,
                    api_key=deepseek_key,
                    base_url=deepseek_base,
                    callbacks=[Monitor()]
                )
                self.llm = llm

                llm_with_tools = llm.bind_tools(
                    self.available_tools,
                    tool_choice="auto",
                    strict=False,
                    parallel_tool_calls=False,
                )
                self.llm_with_tools = llm_with_tools
        
                if prompt is None:
                    await self.run_chat()
                else:
                    await self.process_query(prompt)


def parse_args():
    parser = argparse.ArgumentParser(description="MCP scanner chatbot client")
    parser.add_argument(
        "--llm",
        choices=("deepseek",),
        default="deepseek",
        help="LLM provider (default: deepseek)",
    )
    parser.add_argument(
        "--prompt",
        help="Run one prompt and exit; omit it to start interactive chat",
    )
    parser.add_argument(
        "--target",
        help="默认网段(CIDR)：未指定时由 LLM 调用 get_local_network 获取",
    )
    parser.add_argument(
        "--ports",
        help="默认端口：未指定时用常见端口，也支持 top/web/all 等别名",
    )
    return parser.parse_args()


async def main():
    args = parse_args()
    default_network = args.target or os.getenv("DEFAULT_NETWORK") or None
    if default_network:
        cleaned, note = clean_network_note(default_network)
        if cleaned:
            default_network = narrow_to_prefix(cleaned)
            if note:
                print(f"⚠️ {note}")
        else:
            print(f"⚠️ 忽略无法识别的默认网段：{default_network}")
            default_network = None
    raw_ports = args.ports or os.getenv("DEFAULT_PORTS")
    if raw_ports:
        default_ports, note = normalize_ports(raw_ports)
        if note:
            print(f"⚠️ {note}")
    else:
        default_ports = COMMON_PORTS
    print(
        f"MCP 服务：{MCP_SERVER_URL}｜默认端口：{default_ports}｜"
        f"默认网段：{default_network or '由 LLM 调用工具获取'}"
    )
    chatbot = ScannerBot(default_network=default_network, default_ports=default_ports)
    await chatbot.connect_to_server_and_run(prompt=args.prompt)
  

if __name__ == "__main__":
    asyncio.run(main())

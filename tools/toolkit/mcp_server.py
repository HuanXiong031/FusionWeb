"""toolkit MCP server：把镜像内工具以 MCP 工具形式暴露给 DSH 红队模式。

接入方式：DSH 的 dsh-mcp-studio 指向 http://fusionweb-toolkit:7000/mcp
（streamable-http 传输）。

每个 MCP 工具都带一句"纪律说明"（速率默认、主动扫描需先登记资产、产物落盘位置），
实际执行统一走 runner.run_tool：白名单 + 速率纪律 + 产物落盘 + 审计留痕。
"""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from runner import TOOLS, ToolError, run_tool

PORT = int(os.environ.get("TOOLKIT_MCP_PORT", "7000"))
WORKSPACE_HINT = os.environ.get("TOOLKIT_WORKSPACE", "/workspace")

mcp = FastMCP("fusionweb-toolkit", host="0.0.0.0", port=PORT)


def _describe(name: str) -> str:
    spec = TOOLS[name]
    bits = [f"kind={spec.kind}"]
    if spec.default_rate:
        bits.append(f"默认速率 {spec.rate_flag} {spec.default_rate}（未显式指定时自动注入）")
    if spec.active:
        bits.append("主动扫描：目标应已登记到 assets.md")
    bits.append(f"产物写入 workspace/artifacts/scans/，并追加 evidence-index.md 一行")
    return f"{name}（{spec.binary}）：" + "；".join(bits)


def _run(tool: str, args: str, workspace: str, timeout: int) -> dict:
    try:
        return run_tool(tool, args=args, workspace=workspace, timeout=timeout)
    except ToolError as err:
        return {"error": str(err)}


@mcp.tool(description=_describe("nmap_scan"))
def toolkit_nmap_scan(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 600) -> dict:
    """执行 nmap（默认附加 -Pn；不要用 --script 之外的越界参数）。"""
    return _run("nmap_scan", f"-Pn {args}" if "-Pn" not in args else args, workspace, timeout)


@mcp.tool(description=_describe("masscan_scan"))
def toolkit_masscan_scan(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 600) -> dict:
    """执行 masscan（大范围端口发现）。"""
    return _run("masscan_scan", args, workspace, timeout)


@mcp.tool(description=_describe("naabu_scan"))
def toolkit_naabu_scan(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 600) -> dict:
    """执行 naabu（端口扫描）。"""
    return _run("naabu_scan", args, workspace, timeout)


@mcp.tool(description=_describe("httpx_probe"))
def toolkit_httpx_probe(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 300) -> dict:
    """执行 httpx（存活与指纹探测）。"""
    return _run("httpx_probe", args, workspace, timeout)


@mcp.tool(description=_describe("nuclei_scan"))
def toolkit_nuclei_scan(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 900) -> dict:
    """执行 nuclei（模板扫描；模板已随镜像内置）。"""
    return _run("nuclei_scan", args, workspace, timeout)


@mcp.tool(description=_describe("subfinder_enum"))
def toolkit_subfinder_enum(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 300) -> dict:
    """执行 subfinder（被动子域枚举）。"""
    return _run("subfinder_enum", args, workspace, timeout)


@mcp.tool(description=_describe("dnsx_resolve"))
def toolkit_dnsx_resolve(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 300) -> dict:
    """执行 dnsx（DNS 解析/校验）。"""
    return _run("dnsx_resolve", args, workspace, timeout)


@mcp.tool(description=_describe("ffuf_fuzz"))
def toolkit_ffuf_fuzz(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 600) -> dict:
    """执行 ffuf（目录/参数模糊测试；字典需显式给出 -w）。"""
    return _run("ffuf_fuzz", args, workspace, timeout)


@mcp.tool(description=_describe("semgrep_scan"))
def semgrep_scan(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 900) -> dict:
    """执行 semgrep（静态代码审计）。"""
    return _run("semgrep_scan", args, workspace, timeout)


@mcp.tool(description=_describe("gitleaks_scan"))
def gitleaks_scan(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 600) -> dict:
    """执行 gitleaks（密钥/凭据泄露扫描）。"""
    return _run("gitleaks_scan", args, workspace, timeout)


@mcp.tool(description=_describe("jadx_decompile"))
def jadx_decompile(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 900) -> dict:
    """执行 jadx（APK/DEX 反编译）。"""
    return _run("jadx_decompile", args, workspace, timeout)


@mcp.tool(description=_describe("apktool_decode"))
def apktool_decode(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 600) -> dict:
    """执行 apktool（APK 解包/重打包）。"""
    return _run("apktool_decode", args, workspace, timeout)


@mcp.tool(description=_describe("binwalk_extract"))
def binwalk_extract(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 600) -> dict:
    """执行 binwalk（固件/二进制提取分析）。"""
    return _run("binwalk_extract", args, workspace, timeout)


@mcp.tool(description=_describe("yara_scan"))
def yara_scan(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 600) -> dict:
    """执行 yara（规则匹配扫描）。"""
    return _run("yara_scan", args, workspace, timeout)


@mcp.tool(description=_describe("volatility_scan"))
def volatility_scan(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 900) -> dict:
    """执行 volatility3（内存取证/应急溯源）。"""
    return _run("volatility_scan", args, workspace, timeout)


@mcp.tool(description=_describe("mingw_build"))
def mingw_build(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 600) -> dict:
    """执行 mingw-w64 gcc（Windows 交叉编译）。"""
    return _run("mingw_build", args, workspace, timeout)


@mcp.tool(description=_describe("nasm_assemble"))
def nasm_assemble(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 300) -> dict:
    """执行 nasm（汇编）。"""
    return _run("nasm_assemble", args, workspace, timeout)


@mcp.tool(description=_describe("upx_pack"))
def upx_pack(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 300) -> dict:
    """执行 upx（可执行文件压缩/加壳）。"""
    return _run("upx_pack", args, workspace, timeout)


@mcp.tool(description=_describe("kubectl_run"))
def kubectl_run(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 300) -> dict:
    """执行 kubectl（云原生/K8s 操作；需先提供集群凭据）。"""
    return _run("kubectl_run", args, workspace, timeout)


@mcp.tool(description=_describe("aws_cli"))
def aws_cli(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 300) -> dict:
    """执行 awscli（云平台操作；需先提供凭据）。"""
    return _run("aws_cli", args, workspace, timeout)


@mcp.tool(description=_describe("tsk_fls"))
def tsk_fls(args: str, workspace: str = WORKSPACE_HINT, timeout: int = 600) -> dict:
    """执行 Sleuth Kit fls（磁盘镜像文件列表，应急取证）。"""
    return _run("tsk_fls", args, workspace, timeout)


@mcp.tool()
def toolkit_tools() -> dict:
    """列出 toolkit 内的全部工具白名单及纪律参数。"""
    from runner import list_tools

    return {"workspace": WORKSPACE_HINT, "tools": list_tools()}


def main() -> None:
    print(f"[mcp] toolkit MCP server 监听 0.0.0.0:{PORT}/mcp（streamable-http）", flush=True)
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()

"""toolkit 工具执行核心：白名单、速率纪律、产物落盘、审计留痕。

设计对齐 dsh-scanner-tools 的行为契约：
  * 只允许白名单内的工具；
  * 工具支持速率参数时，未显式指定则注入保守默认值（并在审计里留痕）；
  * 每次调用的 stdout/stderr 落盘到 <workspace>/artifacts/scans/，并追加一行到
    <workspace>/evidence-index.md（"证据索引"）；
  * 每次调用追加一行 JSONL 审计（toolkit-audit）。
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# 允许的工作区根目录（冒号分隔）：worker 用 /app/data（与宿主共享盘），DSH 用 /workspace
WORKSPACE_ROOTS = [
    Path(item.strip())
    for item in os.environ.get(
        "TOOLKIT_WORKSPACES", os.environ.get("TOOLKIT_WORKSPACE", "/workspace")
    ).split(":")
    if item.strip()
]
WORKSPACE_ROOT = WORKSPACE_ROOTS[0]
AUDIT_LOG = Path(os.environ.get("TOOLKIT_AUDIT_LOG", "/var/log/toolkit/audit.jsonl"))
MAX_CONCURRENCY = int(os.environ.get("TOOLKIT_MAX_CONCURRENCY", "8"))
DEFAULT_TIMEOUT = int(os.environ.get("TOOLKIT_DEFAULT_TIMEOUT", "300"))

# 危险参数/路径：避免越界读写宿主或容器敏感路径
_FORBIDDEN_ARG = re.compile(r"(^|\s)(--config\s+/etc/|/proc/|/sys/|/dev/mem)")


@dataclass
class ToolSpec:
    name: str
    binary: str
    rate_flag: str | None = None          # 速率参数（未指定时注入默认值）
    default_rate: str | None = None
    active: bool = False                  # True=主动扫描（需要目标已登记）
    kind: str = "scan"
    extra_flags: list[str] = field(default_factory=list)


# 工具白名单（L1 扫描 / L2 审计逆向 / L3 免杀编译 / L4 应急云）
TOOLS: dict[str, ToolSpec] = {
    # L1 扫描类
    "nmap_scan": ToolSpec("nmap_scan", "nmap", kind="scan", extra_flags=["-Pn"]),
    "masscan_scan": ToolSpec("masscan_scan", "masscan", rate_flag="--rate", default_rate="1000", active=True),
    "naabu_scan": ToolSpec("naabu_scan", "naabu", rate_flag="-rate", default_rate="1000", active=True),
    "httpx_probe": ToolSpec("httpx_probe", "httpx", rate_flag="-rl", default_rate="25"),
    "nuclei_scan": ToolSpec("nuclei_scan", "nuclei", rate_flag="-rl", default_rate="15", active=True),
    "subfinder_enum": ToolSpec("subfinder_enum", "subfinder", kind="recon"),
    "dnsx_resolve": ToolSpec("dnsx_resolve", "dnsx", kind="recon"),
    "ffuf_fuzz": ToolSpec("ffuf_fuzz", "ffuf", rate_flag="-rate", default_rate="50", active=True),
    # L2 审计 / 逆向
    "semgrep_scan": ToolSpec("semgrep_scan", "semgrep", kind="audit"),
    "gitleaks_scan": ToolSpec("gitleaks_scan", "gitleaks", kind="audit"),
    "jadx_decompile": ToolSpec("jadx_decompile", "jadx", kind="reverse"),
    "apktool_decode": ToolSpec("apktool_decode", "apktool", kind="reverse"),
    "binwalk_extract": ToolSpec("binwalk_extract", "binwalk", kind="reverse"),
    "yara_scan": ToolSpec("yara_scan", "yara", kind="audit"),
    "volatility_scan": ToolSpec("volatility_scan", "vol", kind="forensics"),
    # L3 免杀 / 编译
    "mingw_build": ToolSpec("mingw_build", "x86_64-w64-mingw32-gcc", kind="build"),
    "nasm_assemble": ToolSpec("nasm_assemble", "nasm", kind="build"),
    "upx_pack": ToolSpec("upx_pack", "upx", kind="build"),
    # L4 应急 / 云
    "kubectl_run": ToolSpec("kubectl_run", "kubectl", kind="cloud"),
    "aws_cli": ToolSpec("aws_cli", "aws", kind="cloud"),
    "tsk_fls": ToolSpec("tsk_fls", "fls", kind="forensics"),
}

_rate_lock = threading.Lock()
_last_call: dict[str, float] = {}
_semaphore = threading.Semaphore(MAX_CONCURRENCY)


class ToolError(Exception):
    """工具调用被拒绝或失败。"""


def list_tools() -> list[dict]:
    return [
        {
            "name": spec.name,
            "binary": spec.binary,
            "kind": spec.kind,
            "active": spec.active,
            "rate_flag": spec.rate_flag,
            "default_rate": spec.default_rate,
        }
        for spec in TOOLS.values()
    ]


def _resolve_workspace(workspace: str | None) -> Path:
    """把调用方给的 workspace 归一到容器内的工作区目录下（禁止越界）。"""
    if not workspace:
        path = WORKSPACE_ROOT
    else:
        candidate = Path(workspace)
        if not candidate.is_absolute():
            candidate = WORKSPACE_ROOT / candidate
        path = candidate
    resolved = path.resolve()
    roots = [r.resolve() for r in WORKSPACE_ROOTS]
    if not any(resolved == root or root in resolved.parents for root in roots):
        allowed = "、".join(str(r) for r in roots)
        raise ToolError(f"workspace 越界：{resolved}（必须位于 {allowed} 之下）")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def _parse_args(args: list[str] | str | None) -> list[str]:
    if args is None:
        return []
    if isinstance(args, str):
        return shlex.split(args)
    return [str(a) for a in args]


def _apply_rate_discipline(spec: ToolSpec, argv: list[str]) -> tuple[list[str], str]:
    """未指定速率参数时注入保守默认值，返回（最终参数, 速率注记）。"""
    if not spec.rate_flag or not spec.default_rate:
        return argv, ""
    if any(a == spec.rate_flag or a.startswith(f"{spec.rate_flag}=") for a in argv):
        return argv, f"显式速率：{spec.rate_flag}"
    return [*argv, spec.rate_flag, spec.default_rate], f"默认 {spec.rate_flag} {spec.default_rate}（保守默认）"


def _audit(record: dict) -> None:
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        record["time"] = datetime.now(timezone.utc).isoformat()
        with AUDIT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:  # 审计失败不影响主流程，但会打印
        print(f"[toolkit] 写入审计日志失败: {record}", flush=True)


def _evidence_note(workspace: Path, text: str) -> None:
    try:
        with (workspace / "evidence-index.md").open("a", encoding="utf-8") as fh:
            fh.write(f"- {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')} {text}\n")
    except Exception:
        pass


def run_tool(
    tool: str,
    args: list[str] | str | None = None,
    workspace: str | None = None,
    timeout: int | None = None,
    stdin: str | None = None,
) -> dict:
    """执行一次白名单内的工具调用，返回结构化结果（含产物路径）。"""
    spec = TOOLS.get(tool)
    if spec is None:
        raise ToolError(f"工具不在白名单内：{tool}（可用：{', '.join(sorted(TOOLS))}）")

    argv = _parse_args(args)
    joined = " ".join(argv)
    if _FORBIDDEN_ARG.search(joined):
        raise ToolError("参数命中禁止模式（不允许访问 /proc、/sys、/dev/mem 或覆写 /etc 配置）")

    ws = _resolve_workspace(workspace)
    argv, rate_note = _apply_rate_discipline(spec, argv)
    full_argv = [spec.binary, *argv]
    timeout = int(timeout or DEFAULT_TIMEOUT)

    # 简单的同工具最小间隔，避免一次性打爆目标
    min_interval = float(os.environ.get("TOOLKIT_MIN_INTERVAL", "0.5"))
    with _rate_lock:
        last = _last_call.get(spec.name, 0.0)
        wait = min_interval - (time.time() - last)
        if wait > 0:
            time.sleep(wait)
        _last_call[spec.name] = time.time()

    artifacts_dir = ws / "artifacts" / "scans"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_path = artifacts_dir / f"{spec.name}-{stamp}.out"
    err_path = artifacts_dir / f"{spec.name}-{stamp}.err"

    started = time.time()
    with _semaphore:
        try:
            proc = subprocess.run(
                full_argv,
                cwd=str(ws),
                input=stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            code, stdout, stderr = proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired as exc:
            code = 124
            stdout = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = f"超时（{timeout}s）后被终止"
        except FileNotFoundError:
            raise ToolError(
                f"工具未安装：{spec.binary}（镜像内缺失，请检查 toolkit 构建）"
            ) from None

    duration_ms = int((time.time() - started) * 1000)
    out_path.write_text(stdout, encoding="utf-8")
    err_path.write_text(stderr, encoding="utf-8")
    note = f"`{spec.name}` 退出码 {code}，耗时 {duration_ms}ms，产物 `{out_path.relative_to(ws)}`"
    if rate_note:
        note += f"，速率注记：{rate_note}"
    _evidence_note(ws, note)
    _audit(
        {
            "tool": spec.name,
            "argv": full_argv,
            "workspace": str(ws),
            "exitCode": code,
            "durationMs": duration_ms,
            "rate": rate_note,
            "artifacts": [str(out_path), str(err_path)],
        }
    )

    return {
        "tool": spec.name,
        "exitCode": code,
        "durationMs": duration_ms,
        "stdout": stdout,
        "stderr": stderr,
        "stdoutTail": _tail(stdout),
        "stderrTail": _tail(stderr),
        "artifacts": {"stdout": str(out_path), "stderr": str(err_path)},
        "rateNote": rate_note,
        "workspace": str(ws),
    }


def _tail(text: str, limit: int = 4000) -> str:
    text = text or ""
    return text if len(text) <= limit else "…（已截断）\n" + text[-limit:]

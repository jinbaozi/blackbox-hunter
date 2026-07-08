#!/usr/bin/env python3
"""Generate a report with required BlackBox Hunter sections."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

REQUIRED_SECTION_TITLES = [
    "执行摘要",
    "预检环境摘要",
    "目标画像摘要",
    "Track A 汇总",
    "Track B 汇总",
    "合并与生命周期摘要",
    "验证摘要",
    "覆盖缺口",
    "沙箱限制",
    "主机例外调用摘要",
    "发现项生命周期汇总",
    "附录证据路径",
]

DISPLAY_VALUES = {
    "verified": "已验证",
    "confirmed_static": "静态确认",
    "candidate": "候选",
    "inconclusive": "结论不足",
    "false_positive": "误报",
    "unknown": "未知",
    "missing": "缺失",
    "none": "无",
    "success": "成功",
    "partial": "部分完成",
    "skipped": "已跳过",
    "failed": "失败",
    "untested": "未测试",
    # B3: distinguishes "sandbox didn't let the PoC run" from a real failure.
    "sandbox_blocked": "被沙箱拦截",
    "poc_error": "PoC 执行错误",
    "sandbox_error": "沙盒执行错误",
}


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def lifecycle_counts(merged: dict[str, Any]) -> dict[str, int]:
    stats = {"verified": 0, "confirmed_static": 0, "candidate": 0, "inconclusive": 0, "false_positive": 0}
    for item in merged.get("merged_findings") or []:
        finding = item.get("finding") or {}
        status = str(finding.get("finding_status", "candidate"))
        stats[status] = stats.get(status, 0) + 1
    for key, value in (merged.get("lifecycle_stats") or {}).items():
        if isinstance(value, int):
            stats[key] = value
    return stats


def artifact_paths(scan_root: Path) -> list[str]:
    names = [
        "env_check.json",
        "target_profile.json",
        "scan_strategy.json",
        "coverage_plan.json",
        "track_a_findings.json",
        "track_b_findings.json",
        "merged_findings.json",
        "coverage_report.json",
        "verified_findings.json",
        "scan_state.json",
    ]
    return [str(scan_root / name) for name in names]


def display_value(value: Any, default: str = "unknown") -> str:
    raw = str(value if value not in (None, "") else default)
    return DISPLAY_VALUES.get(raw, raw)


def display_list(values: list[Any] | None, empty: str = "none") -> str:
    if not values:
        return display_value(empty)
    return ", ".join(str(value) for value in values)


def _render_coverage_gaps(gaps: list[Any]) -> str:
    """A3: render structured gaps as a markdown table.

    Back-compat: gaps may be either ``{kind, target, reason}`` dicts (new
    shape from ``derive_coverage.compute``) or pre-existing flat dicts
    (legacy hand-written ``phase_blocks`` shape). We accept both.
    """
    if not gaps:
        return "缺口: 无"
    if not all(isinstance(g, dict) and {"kind", "target"}.issubset(g.keys()) for g in gaps):
        # Legacy / fallback shape: dump as JSON
        return f"缺口: {json.dumps(gaps, sort_keys=True, ensure_ascii=False)}"
    lines = ["缺口 (结构化):", "", "| kind | target | reason |", "| --- | --- | --- |"]
    for g in gaps:
        kind = display_value(g.get("kind", "unknown"))
        target = str(g.get("target", ""))
        reason = str(g.get("reason", ""))
        lines.append(f"| {kind} | {target} | {reason} |")
    return "\n".join(lines)


def host_exception_invocations(state: dict[str, Any]) -> list[dict[str, Any]]:
    invocations = []
    for item in state.get("error_log") or []:
        if not isinstance(item, dict):
            continue
        if item.get("code") != "host_exception_invoked":
            continue
        invocations.append(item)
    return invocations


def generate_report(scan_root: Path) -> str:
    env = read_json(scan_root / "env_check.json")
    profile = read_json(scan_root / "target_profile.json")
    track_a = read_json(scan_root / "track_a_findings.json")
    track_b = read_json(scan_root / "track_b_findings.json")
    merged = read_json(scan_root / "merged_findings.json")
    coverage = read_json(scan_root / "coverage_report.json")
    verified = read_json(scan_root / "verified_findings.json")
    sandbox = verified.get("sandbox_info") or read_json(scan_root / "sandbox_status.json")
    state = read_json(scan_root / "scan_state.json")

    counts = lifecycle_counts(merged)
    lines: list[str] = ["# BlackBox 安全测试报告", ""]
    lines.extend([
        "## 执行摘要",
        f"扫描 ID: {state.get('scan_id', profile.get('scan_id', display_value('unknown')))}",
        f"发现项总数: {sum(counts.values())}",
        "",
        "## 预检环境摘要",
        f"包管理器: {display_value(env.get('package_manager'))}",
        f"阻断工具: {display_list(env.get('block_decision', {}).get('blocked_tools', []))}",
        f"回退或降级: {display_list(env.get('block_decision', {}).get('warnings', []))}",
        "",
        "## 目标画像摘要",
        f"包类型: {display_value((profile.get('package') or {}).get('type'))}",
        f"提取方法: {display_value((profile.get('extraction') or {}).get('method'))}",
        f"架构: {display_list(profile.get('architectures'), 'unknown')}",
        "",
        "## Track A 汇总",
        f"状态: {display_value(track_a.get('status', 'missing'))}",
        f"信号数量: {(track_a.get('metadata') or {}).get('signals_count', 0)}",
        "",
        "## Track B 汇总",
        f"状态: {display_value(track_b.get('status', 'missing'))}",
        f"分析维度: {display_list((track_b.get('metadata') or {}).get('dimensions_analyzed', []))}",
        "",
        "## 合并与生命周期摘要",
        f"去重统计: {json.dumps(merged.get('dedup_stats', {}), sort_keys=True)}",
        f"生命周期统计: {json.dumps(counts, sort_keys=True)}",
        "",
        "## 验证摘要",
        f"验证统计: {json.dumps(verified.get('verification_stats', {}), sort_keys=True)}",
        "",
        "## 覆盖缺口",
        _render_coverage_gaps(coverage.get("gaps", [])),
        "",
        "## 沙箱限制",
        f"引擎: {display_value(sandbox.get('engine', 'none'), 'none')}",
        f"限制: {json.dumps(sandbox.get('limitations', []), sort_keys=True)}",
        "",
        "## 主机例外调用摘要",
    ])
    invocations = host_exception_invocations(state)
    if invocations:
        phase_3 = state.get("phase_status", {}).get("phase_3", {})
        lines.append(f"执行模式: {display_value(phase_3.get('execution_mode'))}")
        for invocation in invocations:
            lines.append(
                f"- 例外 ID: {invocation.get('host_exception_id', display_value('unknown'))}; "
                f"原因: {invocation.get('reason', display_value('unknown'))}"
            )
    else:
        lines.append("无主机例外调用。")
    lines.extend([
        "",
        "## 发现项生命周期汇总",
    ])
    for status in ["verified", "confirmed_static", "candidate", "inconclusive", "false_positive"]:
        lines.append(f"- {display_value(status)}: {counts.get(status, 0)}")
    lines.extend(["", "## 附录证据路径"])
    for path in artifact_paths(scan_root):
        lines.append(f"- {path}")
    lines.append("")
    return "\n".join(lines)


def validate_required_sections(report: str) -> list[str]:
    missing = []
    for title in REQUIRED_SECTION_TITLES:
        if f"## {title}" not in report:
            missing.append(title)
    return missing


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate BlackBox Hunter report")
    parser.add_argument("scan_root")
    parser.add_argument("--output", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = generate_report(Path(args.scan_root))
    missing = validate_required_sections(report)
    if missing:
        raise SystemExit("missing report sections: " + ", ".join(missing))
    output = Path(args.output) if args.output else Path(args.scan_root) / "report" / "blackbox-security-report.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

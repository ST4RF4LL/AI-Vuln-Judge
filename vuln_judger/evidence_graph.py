from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import CodeEvidence, EvidenceKind, SourceLocation


FLOW_KINDS = {"SARIF_CODE_FLOW", "DATA_FLOW", "CALL_CHAIN"}
STATUS_BY_STRENGTH = {
    "STRONG": "verified",
    "MEDIUM": "verified",
    "PARTIAL": "partial",
    "WEAK": "break",
}


def build_evidence_graph(evidence: Sequence[Any], disputed_points: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    builder = _EvidenceGraphBuilder()
    normalized = [_evidence_dict(item) for item in evidence]
    report_nodes = []
    source_nodes = []
    for item in normalized:
        kind = str(item.get("kind") or "")
        evidence_id = str(item.get("evidence_id") or "")
        if kind == "REPORT":
            label = _report_label(item)
            node = builder.node(label, "REPORT", "verified", evidence_id, item.get("summary") or "")
            report_nodes.append(node)
            for location in _data_list(item, "locations"):
                target = builder.location_node(location, "SOURCE_LOCATION", "partial", evidence_id)
                source_nodes.append(target)
                builder.edge(node, target, "报告位置", "partial", evidence_id)
        elif kind == "SOURCE_LOCATION":
            status = "verified" if _data_bool(item, "line_exists") else "break"
            for location in item.get("locations") or []:
                node = builder.location_node(location, "SOURCE_LOCATION", status, evidence_id)
                source_nodes.append(node)
                if report_nodes:
                    builder.edge(report_nodes[0], node, "源码解析", status, evidence_id)

    anchor = source_nodes[0] if source_nodes else report_nodes[0] if report_nodes else None
    for item in normalized:
        kind = str(item.get("kind") or "")
        if kind in FLOW_KINDS:
            anchor = _add_flow(builder, item, anchor)

    for item in normalized:
        _add_evidence_breaks(builder, item, anchor)
    for point in disputed_points or []:
        if str(point).strip():
            builder.break_node(f"争议未闭环：{str(point).strip()}", [], anchor)

    if not any(str(item.get("kind") or "") in FLOW_KINDS for item in normalized):
        builder.break_node("未获得可串联的调用链或源到汇数据流证据。", [], anchor)

    graph = builder.graph()
    graph["mermaid"] = graph_to_mermaid(graph)
    graph["ascii"] = graph_to_ascii(graph)
    return graph


def graph_to_markdown(graph: Dict[str, Any]) -> str:
    if not graph:
        return "### 证据串联图\n\n无可展示的证据路径图。\n"
    lines = [
        "### 证据串联图",
        "",
        "```mermaid",
        str(graph.get("mermaid") or "flowchart LR"),
        "```",
        "",
        "#### 调用链 / 数据流概览",
        "",
        "```text",
        str(graph.get("ascii") or "无"),
        "```",
        "",
    ]
    breaks = graph.get("breaks") or []
    if breaks:
        lines.extend(["#### 断链 / 未闭环点", ""])
        for item in breaks:
            evidence_ids = item.get("evidence_ids") or []
            suffix = f"（证据：{', '.join(evidence_ids)}）" if evidence_ids else ""
            lines.append(f"- {item.get('label') or item.get('reason') or '未闭环'}{suffix}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def graph_to_mermaid(graph: Dict[str, Any]) -> str:
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    lines = ["flowchart LR"]
    if not nodes:
        lines.append('  empty["无证据路径"]')
        return "\n".join(lines)
    for node in nodes:
        shape = "{{{label}}}" if node.get("status") == "break" else "[{label}]"
        label = _mermaid_label(node.get("label") or node.get("id") or "节点")
        lines.append(f"  {node.get('id')}{shape.format(label=label)}")
    for edge in edges:
        style = "-.->" if edge.get("status") == "break" else "-->"
        label = _mermaid_label(edge.get("label") or "")
        if label:
            lines.append(f"  {edge.get('from')} {style}|{label}| {edge.get('to')}")
        else:
            lines.append(f"  {edge.get('from')} {style} {edge.get('to')}")
    lines.extend(
        [
            "  classDef verified fill:#ecfdf5,stroke:#059669,color:#064e3b;",
            "  classDef partial fill:#fffbeb,stroke:#d97706,color:#78350f;",
            "  classDef break fill:#fef2f2,stroke:#dc2626,color:#7f1d1d;",
        ]
    )
    for node in nodes:
        status = node.get("status")
        if status in {"verified", "partial", "break"}:
            lines.append(f"  class {node.get('id')} {status};")
    return "\n".join(lines)


def graph_to_ascii(graph: Dict[str, Any]) -> str:
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    if not nodes:
        return "无证据路径"
    outgoing: Dict[str, List[Dict[str, Any]]] = {}
    incoming = set()
    for edge in edges:
        outgoing.setdefault(str(edge.get("from")), []).append(edge)
        incoming.add(str(edge.get("to")))
    starts = [node for node in nodes if str(node.get("id")) not in incoming] or nodes[:1]
    seen = set()
    lines: List[str] = []

    def walk(node_id: str, depth: int) -> None:
        if node_id in seen:
            lines.append("  " * depth + f"↳ {_node_label(nodes, node_id)}（已在上方出现）")
            return
        seen.add(node_id)
        lines.append("  " * depth + f"- {_node_label(nodes, node_id)}")
        for edge in outgoing.get(node_id, [])[:8]:
            status = "断链" if edge.get("status") == "break" else "部分" if edge.get("status") == "partial" else "连接"
            lines.append("  " * (depth + 1) + f"{status}: {edge.get('label') or ''}")
            walk(str(edge.get("to")), depth + 2)

    for start in starts[:4]:
        walk(str(start.get("id")), 0)
    return "\n".join(lines)


class _EvidenceGraphBuilder:
    def __init__(self) -> None:
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self.breaks: List[Dict[str, Any]] = []
        self._node_by_key: Dict[str, str] = {}
        self._counter = 0

    def node(self, label: str, kind: str, status: str, evidence_id: str = "", detail: str = "") -> str:
        key = f"{kind}:{label}:{status}"
        if key in self._node_by_key:
            node_id = self._node_by_key[key]
            if evidence_id:
                self._add_evidence_id(node_id, evidence_id)
            return node_id
        node_id = f"g{self._counter}"
        self._counter += 1
        payload = {
            "id": node_id,
            "label": label[:160],
            "kind": kind,
            "status": status,
            "detail": str(detail or "")[:500],
            "evidence_ids": [evidence_id] if evidence_id else [],
        }
        self.nodes.append(payload)
        self._node_by_key[key] = node_id
        return node_id

    def location_node(self, location: Any, kind: str, status: str, evidence_id: str = "") -> str:
        label = _location_text(location)
        return self.node(label, kind, status, evidence_id, label)

    def edge(self, source: str, target: str, label: str, status: str, evidence_id: str = "") -> None:
        if not source or not target or source == target:
            return
        key = (source, target, label, status)
        for edge in self.edges:
            if (edge.get("from"), edge.get("to"), edge.get("label"), edge.get("status")) == key:
                if evidence_id and evidence_id not in edge["evidence_ids"]:
                    edge["evidence_ids"].append(evidence_id)
                return
        self.edges.append(
            {
                "from": source,
                "to": target,
                "label": label[:120],
                "status": status,
                "evidence_ids": [evidence_id] if evidence_id else [],
            }
        )

    def break_node(self, reason: str, evidence_ids: Sequence[str], anchor: Optional[str]) -> str:
        node = self.node(f"断链：{reason}", "BREAK", "break", evidence_ids[0] if evidence_ids else "", reason)
        if anchor:
            self.edge(anchor, node, "断链/未闭环", "break", evidence_ids[0] if evidence_ids else "")
        payload = {"label": reason[:240], "reason": reason[:500], "evidence_ids": list(evidence_ids)}
        if payload not in self.breaks:
            self.breaks.append(payload)
        return node

    def graph(self) -> Dict[str, Any]:
        return {"version": 1, "nodes": self.nodes, "edges": self.edges, "breaks": self.breaks}

    def _add_evidence_id(self, node_id: str, evidence_id: str) -> None:
        for node in self.nodes:
            if node.get("id") == node_id and evidence_id not in node["evidence_ids"]:
                node["evidence_ids"].append(evidence_id)
                return


def _add_flow(builder: _EvidenceGraphBuilder, item: Dict[str, Any], anchor: Optional[str]) -> Optional[str]:
    evidence_id = str(item.get("evidence_id") or "")
    kind = str(item.get("kind") or "")
    strength = str(item.get("strength") or "")
    status = STATUS_BY_STRENGTH.get(strength, "partial")
    locations = list(item.get("locations") or [])
    if not locations:
        node = builder.node(_flow_label(item), kind, status, evidence_id, item.get("summary") or "")
        if anchor:
            builder.edge(anchor, node, _kind_label(kind), status, evidence_id)
        return node
    previous = anchor
    first = None
    for location in locations:
        node = builder.location_node(location, kind, status, evidence_id)
        if first is None:
            first = node
        if previous:
            builder.edge(previous, node, _kind_label(kind), status, evidence_id)
        previous = node
    _add_call_edges(builder, item, first or anchor, status)
    _add_partial_flow_break(builder, item, previous or anchor)
    return previous or first or anchor


def _add_call_edges(builder: _EvidenceGraphBuilder, item: Dict[str, Any], center: Optional[str], status: str) -> None:
    data = item.get("data") if isinstance(item.get("data"), dict) else {}
    evidence_id = str(item.get("evidence_id") or "")
    symbols = data.get("symbols") if isinstance(data.get("symbols"), list) else []
    symbol_node = center
    if symbols:
        symbol_node = builder.node(f"符号：{symbols[0]}", "SYMBOL", status, evidence_id, item.get("summary") or "")
        if center:
            builder.edge(center, symbol_node, "定位符号", status, evidence_id)
    for caller in _entry_list(data.get("callers"))[:5]:
        caller_node = builder.node(_entry_label(caller), "CALLER", status, evidence_id, _entry_label(caller))
        if symbol_node:
            builder.edge(caller_node, symbol_node, "调用", status, evidence_id)
    for callee in _entry_list(data.get("callees"))[:5]:
        callee_node = builder.node(_entry_label(callee), "CALLEE", status, evidence_id, _entry_label(callee))
        if symbol_node:
            builder.edge(symbol_node, callee_node, "调用", status, evidence_id)


def _add_partial_flow_break(builder: _EvidenceGraphBuilder, item: Dict[str, Any], anchor: Optional[str]) -> None:
    evidence_id = str(item.get("evidence_id") or "")
    data = item.get("data") if isinstance(item.get("data"), dict) else {}
    step_count = _int_or_none(data.get("step_count"))
    verified_count = _int_or_none(data.get("verified_step_count"))
    if step_count is not None and verified_count is not None and verified_count < step_count:
        builder.break_node(f"{item.get('kind')} 只解析 {verified_count}/{step_count} 个步骤", [evidence_id], anchor)
    if data.get("partial_result"):
        builder.break_node(f"{item.get('kind')} 返回 partial 结果", [evidence_id], anchor)


def _add_evidence_breaks(builder: _EvidenceGraphBuilder, item: Dict[str, Any], anchor: Optional[str]) -> None:
    evidence_id = str(item.get("evidence_id") or "")
    kind = str(item.get("kind") or "")
    strength = str(item.get("strength") or "")
    summary = str(item.get("summary") or "")
    data = item.get("data") if isinstance(item.get("data"), dict) else {}
    if kind == "TOOL_DIAGNOSTIC" and _looks_like_break(summary, data):
        builder.break_node(summary, [evidence_id], anchor)
    if kind in FLOW_KINDS and strength in {"PARTIAL", "WEAK"}:
        builder.break_node(f"{_kind_label(kind)} 证据强度为 {strength}：{summary}", [evidence_id], anchor)
    missing = data.get("missing_evidence")
    if isinstance(missing, list):
        for item_name in missing[:6]:
            builder.break_node(f"缺失证据：{item_name}", [evidence_id], anchor)


def _looks_like_break(summary: str, data: Dict[str, Any]) -> bool:
    if data.get("mcp_success") is False or data.get("trace_supported") is False:
        return True
    normalized = summary.lower()
    markers = ("未", "失败", "缺失", "断链", "partial", "no data", "empty", "not found", "无法")
    return any(marker in normalized for marker in markers)


def _evidence_dict(item: Any) -> Dict[str, Any]:
    if isinstance(item, CodeEvidence):
        return {
            "evidence_id": item.evidence_id,
            "kind": item.kind.value,
            "strength": item.strength.value,
            "summary": item.summary,
            "source": item.source,
            "locations": list(item.locations),
            "snippet": item.snippet,
            "data": dict(item.data),
        }
    return item if isinstance(item, dict) else {}


def _report_label(item: Dict[str, Any]) -> str:
    data = item.get("data") if isinstance(item.get("data"), dict) else {}
    rule_id = data.get("rule_id") or item.get("rule_id") or "输入报告"
    message = data.get("message") or item.get("summary") or ""
    return f"报告：{rule_id} {message}".strip()


def _flow_label(item: Dict[str, Any]) -> str:
    return f"{_kind_label(str(item.get('kind') or ''))}: {item.get('summary') or item.get('evidence_id') or ''}".strip()


def _kind_label(kind: str) -> str:
    return {
        "SARIF_CODE_FLOW": "SARIF 代码流",
        "DATA_FLOW": "数据流",
        "CALL_CHAIN": "调用链",
        "SOURCE_LOCATION": "源码位置",
        "REPORT": "输入报告",
    }.get(kind, kind or "证据")


def _location_text(location: Any) -> str:
    if isinstance(location, SourceLocation):
        return location.display()
    if isinstance(location, dict):
        file = str(location.get("file") or "")
        line = location.get("line")
        column = location.get("column")
        symbol = location.get("symbol")
        text = file
        if line not in (None, ""):
            text += f":{line}" if text else f"line {line}"
            if column not in (None, ""):
                text += f":{column}"
        if symbol:
            text += f" ({symbol})"
        return text or str(location)
    text = str(location)
    if re.match(r"^\d+(?::\d+)?$", text):
        return f"line {text}"
    return text


def _data_list(item: Dict[str, Any], key: str) -> List[Any]:
    data = item.get("data") if isinstance(item.get("data"), dict) else {}
    value = data.get(key)
    return value if isinstance(value, list) else []


def _data_bool(item: Dict[str, Any], key: str) -> bool:
    data = item.get("data") if isinstance(item.get("data"), dict) else {}
    return bool(data.get(key))


def _entry_list(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _entry_label(entry: Dict[str, Any]) -> str:
    name = entry.get("qualified_name") or entry.get("name") or entry.get("symbol") or entry.get("function") or "未知符号"
    file = entry.get("file") or entry.get("path") or entry.get("uri") or ""
    line = entry.get("line")
    suffix = f" @ {file}:{line}" if file and line else f" @ {file}" if file else ""
    return f"{name}{suffix}"


def _int_or_none(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _mermaid_label(value: Any) -> str:
    text = str(value or "").replace("\\", "\\\\").replace('"', "'")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:120]


def _node_label(nodes: Sequence[Dict[str, Any]], node_id: str) -> str:
    for node in nodes:
        if str(node.get("id")) == node_id:
            status = node.get("status")
            suffix = " [断链]" if status == "break" else " [部分]" if status == "partial" else ""
            evidence_ids = node.get("evidence_ids") or []
            evidence_text = f" ({', '.join(evidence_ids[:3])})" if evidence_ids else ""
            return f"{node.get('label')}{suffix}{evidence_text}"
    return node_id

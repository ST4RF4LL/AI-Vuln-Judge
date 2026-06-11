from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

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
    graph["path_overview"] = graph_to_path_overview(graph)
    return graph


def graph_to_markdown(graph: Dict[str, Any]) -> str:
    if not graph:
        return "### 调用链 / 数据流概览\n\n无可展示的调用链或数据流。\n"
    lines = [
        "### 调用链 / 数据流概览",
        "",
        str(graph.get("path_overview") or graph_to_path_overview(graph) or "无可展示的调用链或数据流。"),
    ]
    return "\n".join(lines).rstrip() + "\n"


def graph_to_path_overview(graph: Dict[str, Any]) -> str:
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    breaks = graph.get("breaks") or []
    node_by_id = {str(node.get("id")): node for node in nodes if isinstance(node, dict)}
    lines: List[str] = []
    lines.extend(_category_overview_lines("调用链", node_by_id, edges, {"调用链", "调用", "定位符号"}, breaks))
    lines.append("")
    lines.extend(_category_overview_lines("数据流", node_by_id, edges, {"数据流", "SARIF 代码流"}, breaks))
    if breaks:
        lines.extend(["", "未闭环点："])
        for item in breaks:
            reason = _clean_display_text(item.get("label") or item.get("reason") or "未闭环")
            lines.append(f"- {reason}")
    return "\n".join(lines).rstrip()


def graph_to_ascii(graph: Dict[str, Any]) -> str:
    return graph_to_path_overview(graph)


def _category_overview_lines(
    title: str,
    node_by_id: Dict[str, Dict[str, Any]],
    edges: Sequence[Dict[str, Any]],
    labels: set[str],
    breaks: Sequence[Dict[str, Any]],
) -> List[str]:
    category_edges = [
        edge for edge in edges if str(edge.get("label") or "") in labels and not _is_context_anchor_edge(edge, node_by_id)
    ]
    lines = [f"{title}状态：{_path_status(category_edges, breaks)}", ""]
    if not category_edges:
        lines.append(f"{title}：未获得可展示路径。")
        return lines
    for index, component in enumerate(_edge_components(category_edges), start=1):
        lines.append(f"{title} {index}：")
        lines.extend(_vertical_component_lines(component, node_by_id))
        lines.append("")
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def _edge_components(edges: Sequence[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    remaining = list(edges)
    components: List[List[Dict[str, Any]]] = []
    while remaining:
        seed = remaining.pop(0)
        component = [seed]
        node_ids = {str(seed.get("from")), str(seed.get("to"))}
        changed = True
        while changed:
            changed = False
            next_remaining: List[Dict[str, Any]] = []
            for edge in remaining:
                from_id = str(edge.get("from"))
                to_id = str(edge.get("to"))
                if from_id in node_ids or to_id in node_ids:
                    component.append(edge)
                    node_ids.update({from_id, to_id})
                    changed = True
                else:
                    next_remaining.append(edge)
            remaining = next_remaining
        components.append(component)
    return components


def _vertical_component_lines(edges: Sequence[Dict[str, Any]], node_by_id: Dict[str, Dict[str, Any]]) -> List[str]:
    outgoing: Dict[str, List[Dict[str, Any]]] = {}
    incoming: set[str] = set()
    node_ids: List[str] = []
    for edge in edges:
        from_id = str(edge.get("from"))
        to_id = str(edge.get("to"))
        outgoing.setdefault(from_id, []).append(edge)
        incoming.add(to_id)
        if from_id not in node_ids:
            node_ids.append(from_id)
        if to_id not in node_ids:
            node_ids.append(to_id)
    starts = [node_id for node_id in node_ids if node_id not in incoming] or node_ids[:1]
    seen_edges: set[Tuple[str, str, str, str]] = set()
    lines: List[str] = []

    def walk(node_id: str, depth: int, stack: set[str]) -> None:
        lines.append("  " * depth + _overview_node_label(node_by_id.get(node_id), node_id))
        if node_id in stack:
            lines.append("  " * (depth + 1) + "↳ 循环调用，已在上方出现。")
            return
        next_stack = set(stack)
        next_stack.add(node_id)
        for edge in outgoing.get(node_id, []):
            edge_key = (
                str(edge.get("from")),
                str(edge.get("to")),
                str(edge.get("label") or ""),
                str(edge.get("status") or ""),
            )
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            lines.append("  " * (depth + 1) + f"↓ {_overview_edge_label(edge)}")
            walk(str(edge.get("to")), depth + 1, next_stack)

    for start in starts:
        walk(start, 0, set())
    for edge in edges:
        edge_key = (
            str(edge.get("from")),
            str(edge.get("to")),
            str(edge.get("label") or ""),
            str(edge.get("status") or ""),
        )
        if edge_key not in seen_edges:
            lines.append(_overview_node_label(node_by_id.get(str(edge.get("from"))), str(edge.get("from"))))
            lines.append(f"  ↓ {_overview_edge_label(edge)}")
            lines.append("  " + _overview_node_label(node_by_id.get(str(edge.get("to"))), str(edge.get("to"))))
            seen_edges.add(edge_key)
    return lines or ["无可展示路径。"]


def _path_status(edges: Sequence[Dict[str, Any]], breaks: Sequence[Dict[str, Any]]) -> str:
    if breaks:
        return "未闭环"
    if not edges:
        return "未获得证据"
    statuses = {str(edge.get("status") or "") for edge in edges}
    if "break" in statuses:
        return "未闭环"
    if "partial" in statuses:
        return "部分闭环"
    return "已闭环"


def _is_context_anchor_edge(edge: Dict[str, Any], node_by_id: Dict[str, Dict[str, Any]]) -> bool:
    source = node_by_id.get(str(edge.get("from"))) or {}
    target = node_by_id.get(str(edge.get("to"))) or {}
    source_kind = str(source.get("kind") or "")
    target_kind = str(target.get("kind") or "")
    return source_kind in {"REPORT", "SOURCE_LOCATION"} and target_kind in FLOW_KINDS


def _overview_edge_label(edge: Dict[str, Any]) -> str:
    label = _clean_display_text(edge.get("label") or "连接")
    if edge.get("status") == "break":
        return f"断链：{label}"
    if edge.get("status") == "partial":
        return f"{label}（部分）"
    return label


def _overview_node_label(node: Optional[Dict[str, Any]], fallback: str) -> str:
    if not node:
        return _clean_display_text(fallback)
    kind = _overview_kind_label(str(node.get("kind") or "节点"))
    status = str(node.get("status") or "")
    suffix = " [断链]" if status == "break" else " [部分]" if status == "partial" else ""
    label = _clean_display_text(node.get("label") or fallback)
    return f"[{kind}] {label}{suffix}".strip()


def _overview_kind_label(kind: str) -> str:
    return {
        "REPORT": "报告",
        "SOURCE_LOCATION": "源码位置",
        "SARIF_CODE_FLOW": "代码流",
        "DATA_FLOW": "数据流",
        "CALL_CHAIN": "调用链",
        "CALLER": "调用方",
        "CALLEE": "被调函数",
        "SYMBOL": "符号",
        "BREAK": "断链",
    }.get(kind, kind or "节点")


def _clean_display_text(value: Any) -> str:
    text = str(value or "")
    text = re.sub(r"\bev-[0-9A-Za-z_-]+\b", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text or "未命名节点"


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
    for caller in _entry_list(data.get("callers")):
        caller_node = builder.node(_entry_label(caller), "CALLER", status, evidence_id, _entry_label(caller))
        if symbol_node:
            builder.edge(caller_node, symbol_node, "调用", status, evidence_id)
    for callee in _entry_list(data.get("callees")):
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
        for item_name in missing:
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

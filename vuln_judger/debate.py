from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence

from .agents import DEFAULT_AFFIRMATIVE_AGENT, DEFAULT_NEGATIVE_AGENT
from .evidence import EvidenceBundle
from .llm import LLMClient
from .models import (
    AgentConfig,
    CodeEvidence,
    DebateRole,
    DebateTurn,
    EvidenceKind,
    EvidenceStrength,
    SourceLocation,
    Verdict,
    VerdictReport,
)


@dataclass
class DebateDecision:
    verdict: Verdict
    confidence: float
    disputed_points: List[str]
    reasoning_summary: str
    recommended_next_steps: List[str]


class DebateOrchestrator:
    def __init__(
        self,
        max_rounds: int = 4,
        llm_client: Optional[LLMClient] = None,
        affirmative_client: Optional[LLMClient] = None,
        negative_client: Optional[LLMClient] = None,
        affirmative_agent: Optional[AgentConfig] = None,
        negative_agent: Optional[AgentConfig] = None,
    ):
        self.max_rounds = max_rounds
        self.affirmative_client = affirmative_client or llm_client
        self.negative_client = negative_client or llm_client
        self.affirmative_agent = _agent_or_default(affirmative_agent, DEFAULT_AFFIRMATIVE_AGENT)
        self.negative_agent = _agent_or_default(negative_agent, DEFAULT_NEGATIVE_AGENT)

    def adjudicate(self, bundle: EvidenceBundle) -> VerdictReport:
        evidence = bundle.evidence
        turns = self._debate_turns(bundle)
        decision = self._decide(bundle)
        return VerdictReport(
            finding_id=bundle.finding.finding_id,
            rule_id=bundle.finding.rule_id,
            verdict=decision.verdict,
            confidence=round(decision.confidence, 2),
            reasoning_summary=decision.reasoning_summary,
            evidence_chain=evidence,
            debate=turns,
            disputed_points=decision.disputed_points,
            protection_assessment=_protection_assessment(evidence),
            impact_assessment=_impact_assessment(evidence),
            source_locations=bundle.finding.locations,
            recommended_next_steps=decision.recommended_next_steps,
        )

    def _debate_turns(self, bundle: EvidenceBundle) -> List[DebateTurn]:
        evidence = bundle.evidence
        location_ids = _ids(evidence, EvidenceKind.SOURCE_LOCATION)
        flow_ids = _ids(evidence, EvidenceKind.SARIF_CODE_FLOW, EvidenceKind.DATA_FLOW, EvidenceKind.CALL_CHAIN)
        protection_ids = _ids(evidence, EvidenceKind.PROTECTION)
        impact_ids = _ids(evidence, EvidenceKind.IMPACT, EvidenceKind.PROJECT_CONTEXT)
        tool_diag_ids = _ids(evidence, EvidenceKind.TOOL_DIAGNOSTIC)
        challenges = self._challenges(bundle)
        affirmative_claim = self._llm_claim(
            "AFFIRMATIVE",
            "论证该静态分析发现是真实漏洞候选。只能引用提示中给出的证据 ID。",
            bundle,
            extra="",
        ) or "该发现有源码证据支撑，应作为真实漏洞候选继续研判。"
        negative_claim = self._llm_claim(
            "NEGATIVE",
            "质疑漏洞主张。重点检查幻觉、可达性、防护措施和影响夸大。只能引用提示中给出的证据 ID。",
            bundle,
            extra="\n".join(challenges),
        ) or (
            "证据必须证明真实代码存在、路径可达、缺少有效防护，且影响没有被夸大。"
            + (" ".join(challenges) if challenges else "未发现主要反证。")
        )
        turns = [
            DebateTurn(
                role=DebateRole.AFFIRMATIVE,
                round_index=1,
                claim=affirmative_claim,
                evidence_ids=location_ids + flow_ids + impact_ids,
            ),
            DebateTurn(
                role=DebateRole.NEGATIVE,
                round_index=1,
                claim=negative_claim,
                evidence_ids=protection_ids + tool_diag_ids,
                resolved=not challenges,
            ),
        ]
        if challenges:
            fallback_reply = self._affirmative_reply(bundle, challenges)
            reply = self._llm_claim(
                "AFFIRMATIVE",
                "回应反方质疑。证据不足时必须承认不确定性。只能引用提示中给出的证据 ID。",
                bundle,
                extra="\n".join(challenges),
            ) or fallback_reply
            answer_ids = location_ids + flow_ids + protection_ids + impact_ids
            turns.append(
                DebateTurn(
                    role=DebateRole.AFFIRMATIVE,
                    round_index=2,
                    claim=reply,
                    evidence_ids=answer_ids,
                    resolved=not _material_unresolved(challenges),
                )
            )
        decision = self._decide(bundle)
        turns.append(
            DebateTurn(
                role=DebateRole.MODERATOR,
                round_index=min(self.max_rounds, 3),
                claim=(
                    f"最终结论：{_verdict_label(decision.verdict)}（{decision.verdict.value}），"
                    f"置信度 {decision.confidence:.2f}。{decision.reasoning_summary}"
                ),
                evidence_ids=[item.evidence_id for item in evidence],
                resolved=decision.verdict != Verdict.INCONCLUSIVE,
            )
        )
        return turns

    def _challenges(self, bundle: EvidenceBundle) -> List[str]:
        evidence = bundle.evidence
        challenges: List[str] = []
        if _all_primary_locations_invalid(evidence):
            challenges.append("报告位置无法在提供的源码树中解析。")
        if not _has_meaningful_flow(evidence):
            challenges.append("尚未建立已验证的源到汇数据流或调用路径。")
        if _has_protection(evidence):
            challenges.append("附近代码存在可能缓解问题的校验、鉴权或消毒逻辑。")
        if _has_cpp_compile_gap(evidence):
            challenges.append("未找到编译数据库，C++ 证据质量受限。")
        if not _has_impact(evidence):
            challenges.append("实际影响尚未关联到资产、权限或可达的危险汇点。")
        challenges.extend(bundle.diagnostics)
        return challenges

    def _llm_claim(self, role: str, task: str, bundle: EvidenceBundle, extra: str) -> Optional[str]:
        client = self.affirmative_client if role == "AFFIRMATIVE" else self.negative_client
        if client is None:
            return None
        agent = self.affirmative_agent if role == "AFFIRMATIVE" else self.negative_agent
        role_label = _role_label(role)
        agent_name = agent.name.strip() or role_label
        agent_instructions = agent.instructions.strip()
        evidence_lines = []
        for item in bundle.evidence[:20]:
            evidence_lines.append(
                f"- {item.evidence_id} | {_evidence_kind_label(item.kind)}（{item.kind.value}） | "
                f"{_evidence_strength_label(item.strength)}（{item.strength.value}） | {item.summary}"
            )
        system = (
            f"你是 {agent_name}，在静态漏洞研判博弈中担任{role_label}。"
            "禁止编造文件、数据流、防护措施或漏洞影响。"
            "每个具体论断都必须引用提示中一个或多个证据 ID。"
        )
        if agent_instructions:
            system += f"\n角色配置：\n{agent_instructions}"
        user = (
            f"任务：{task}\n"
            f"发现：{bundle.finding.rule_id} - {bundle.finding.message}\n"
            f"证据：\n" + "\n".join(evidence_lines) + "\n"
            f"补充上下文或质疑：\n{extra}\n"
            "请用中文写一个简洁的辩论回合，不要使用 Markdown 表格。"
        )
        return client.complete(system, user)

    def _affirmative_reply(self, bundle: EvidenceBundle, challenges: Sequence[str]) -> str:
        evidence = bundle.evidence
        replies = []
        if _has_valid_location(evidence):
            replies.append("SARIF 位置可以解析到真实源码。")
        if _has_meaningful_flow(evidence):
            replies.append("SARIF 或分析器路径提供了可达性/数据流证据。")
        else:
            replies.append("可达性仍未被充分证明。")
        if _has_protection(evidence):
            replies.append("存在防护证据，但需要审查其有效性，不能直接假定有效。")
        if _has_impact(evidence):
            replies.append("影响已从规则/消息和匹配的项目上下文中映射。")
        return " ".join(replies)

    def _decide(self, bundle: EvidenceBundle) -> DebateDecision:
        evidence = bundle.evidence
        challenges = self._challenges(bundle)
        if _all_primary_locations_invalid(evidence):
            return DebateDecision(
                verdict=Verdict.FALSE_POSITIVE,
                confidence=0.9,
                disputed_points=challenges,
                reasoning_summary="该 SARIF 发现无法解析到提供项目中的真实源码位置。",
                recommended_next_steps=["确认 SARIF 报告是否由同一源码版本生成。"],
            )
        if _has_cpp_compile_gap(evidence) and not _has_meaningful_flow(evidence):
            return DebateDecision(
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.45,
                disputed_points=challenges,
                reasoning_summary="该 C++ 发现有真实源码证据，但缺少编译数据库支撑的数据流或调用链确认。",
                recommended_next_steps=["提供 compile_commands.json 或 CodeQL 数据库后重新研判。"],
            )
        if _has_meaningful_flow(evidence) and not _has_protection(evidence):
            return DebateDecision(
                verdict=Verdict.TRUE_POSITIVE,
                confidence=0.82 if _has_project_context(evidence) else 0.76,
                disputed_points=challenges,
                reasoning_summary="该发现可以解析到真实代码，并存在已验证的路径/数据流证据，当前未识别到有效缓解防护。",
                recommended_next_steps=["人工验证利用前提，并根据资产影响确定修复优先级。"],
            )
        if _has_meaningful_flow(evidence) and _has_protection(evidence):
            return DebateDecision(
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.58,
                disputed_points=challenges,
                reasoning_summary="可疑漏洞路径看起来真实，但附近防护逻辑是否有效仍需要人工复核。",
                recommended_next_steps=["审查被引用的防护代码，并测试攻击者可控输入是否能绕过。"],
            )
        if _has_weak_source_sink(evidence) and not _has_protection(evidence):
            return DebateDecision(
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.52,
                disputed_points=challenges,
                reasoning_summary="代码位置存在且包含类似源点/汇点的词项，但源到汇可达性尚未被证明。",
                recommended_next_steps=["启用索引运行 Atlas/CodeQL，或让扫描器在 SARIF 中补充 code-flow 路径。"],
            )
        if _has_protection(evidence):
            return DebateDecision(
                verdict=Verdict.FALSE_POSITIVE,
                confidence=0.62,
                disputed_points=challenges,
                reasoning_summary="该发现对应源码存在，但缺少已验证的漏洞路径，并且附近存在缓解迹象。",
                recommended_next_steps=["在抑制该 SARIF 发现前，确认防护措施确实有效。"],
            )
        return DebateDecision(
            verdict=Verdict.INCONCLUSIVE,
            confidence=0.4,
            disputed_points=challenges,
            reasoning_summary="源码位置存在，但当前证据不足以证明可达性、数据流或缓解状态。",
            recommended_next_steps=["收集更强的分析器证据，或在 SARIF 报告中补充 code-flow。"],
        )


def _ids(evidence: Iterable[CodeEvidence], *kinds: EvidenceKind) -> List[str]:
    accepted = set(kinds)
    return [item.evidence_id for item in evidence if item.kind in accepted]


def _agent_or_default(config: Optional[AgentConfig], default: AgentConfig) -> AgentConfig:
    if config is None:
        return default
    name = config.name.strip() or default.name
    instructions = config.instructions.strip() or default.instructions
    return AgentConfig(
        name=name,
        instructions=instructions,
        role=config.role or default.role,
        profile_id=config.profile_id or default.profile_id,
        path=config.path or default.path,
        starred=config.starred,
        deletable=config.deletable,
        is_default=config.is_default,
    )


def _by_kind(evidence: Iterable[CodeEvidence]) -> Dict[EvidenceKind, List[CodeEvidence]]:
    result: Dict[EvidenceKind, List[CodeEvidence]] = {}
    for item in evidence:
        result.setdefault(item.kind, []).append(item)
    return result


def _all_primary_locations_invalid(evidence: Sequence[CodeEvidence]) -> bool:
    locations = [item for item in evidence if item.kind == EvidenceKind.SOURCE_LOCATION]
    return bool(locations) and all(not item.data.get("line_exists") for item in locations)


def _has_valid_location(evidence: Sequence[CodeEvidence]) -> bool:
    return any(item.kind == EvidenceKind.SOURCE_LOCATION and item.data.get("line_exists") for item in evidence)


def _has_meaningful_flow(evidence: Sequence[CodeEvidence]) -> bool:
    for item in evidence:
        if item.kind == EvidenceKind.SARIF_CODE_FLOW and item.strength == EvidenceStrength.STRONG:
            return True
        if item.kind in {EvidenceKind.DATA_FLOW, EvidenceKind.CALL_CHAIN} and item.strength in {
            EvidenceStrength.STRONG,
            EvidenceStrength.MEDIUM,
        }:
            if item.source != "source-indexer":
                return True
    return False


def _has_weak_source_sink(evidence: Sequence[CodeEvidence]) -> bool:
    return any(item.kind == EvidenceKind.DATA_FLOW and item.source == "source-indexer" for item in evidence)


def _has_protection(evidence: Sequence[CodeEvidence]) -> bool:
    return any(item.kind == EvidenceKind.PROTECTION for item in evidence)


def _has_impact(evidence: Sequence[CodeEvidence]) -> bool:
    return any(item.kind in {EvidenceKind.IMPACT, EvidenceKind.PROJECT_CONTEXT} for item in evidence)


def _has_project_context(evidence: Sequence[CodeEvidence]) -> bool:
    return any(item.kind == EvidenceKind.PROJECT_CONTEXT for item in evidence)


def _has_cpp_compile_gap(evidence: Sequence[CodeEvidence]) -> bool:
    return any(
        item.kind == EvidenceKind.TOOL_DIAGNOSTIC
        and item.source == "source-indexer"
        and item.data.get("compile_database") is None
        and "compile_commands.json" in item.summary
        for item in evidence
    )


def _material_unresolved(challenges: Sequence[str]) -> bool:
    material = (
        "无法",
        "尚未建立",
        "受限",
        "cannot be resolved",
        "No verified",
        "degraded",
        "outside configured",
    )
    return any(any(marker in challenge for marker in material) for challenge in challenges)


def _protection_assessment(evidence: Sequence[CodeEvidence]) -> str:
    protections = [item for item in evidence if item.kind == EvidenceKind.PROTECTION]
    if not protections:
        return "未识别到附近存在校验、鉴权、消毒或限流证据。"
    terms = []
    for item in protections:
        terms.extend(item.data.get("terms", []))
    unique_terms = sorted(set(terms))
    if unique_terms:
        return "路径附近发现可能的缓解控制：" + ", ".join(unique_terms)
    return "发现可能的缓解控制，但其有效性尚未确认。"


def _impact_assessment(evidence: Sequence[CodeEvidence]) -> str:
    impacts = []
    for item in evidence:
        if item.kind == EvidenceKind.IMPACT:
            impacts.extend(item.data.get("impacts", []))
        if item.kind == EvidenceKind.PROJECT_CONTEXT:
            impacts.append(f"相关项目上下文：{item.summary}")
    if not impacts:
        return "未收集到影响证据。"
    return "; ".join(dict.fromkeys(impacts))


def _role_label(role: str) -> str:
    if role == "AFFIRMATIVE":
        return "正方"
    if role == "NEGATIVE":
        return "反方"
    return "主持人"


def _verdict_label(verdict: Verdict) -> str:
    labels = {
        Verdict.TRUE_POSITIVE: "真实漏洞",
        Verdict.FALSE_POSITIVE: "误报",
        Verdict.INCONCLUSIVE: "证据不足",
    }
    return labels.get(verdict, verdict.value)


def _evidence_kind_label(kind: EvidenceKind) -> str:
    labels = {
        EvidenceKind.SOURCE_LOCATION: "源码位置",
        EvidenceKind.SARIF_CODE_FLOW: "SARIF 代码流",
        EvidenceKind.CALL_CHAIN: "调用链",
        EvidenceKind.DATA_FLOW: "数据流",
        EvidenceKind.PROTECTION: "防护证据",
        EvidenceKind.IMPACT: "影响证据",
        EvidenceKind.TOOL_DIAGNOSTIC: "工具诊断",
        EvidenceKind.PROJECT_CONTEXT: "项目上下文",
    }
    return labels.get(kind, kind.value)


def _evidence_strength_label(strength: EvidenceStrength) -> str:
    labels = {
        EvidenceStrength.STRONG: "强",
        EvidenceStrength.MEDIUM: "中",
        EvidenceStrength.WEAK: "弱",
        EvidenceStrength.PARTIAL: "部分",
    }
    return labels.get(strength, strength.value)

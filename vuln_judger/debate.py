from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .agents import DEFAULT_AFFIRMATIVE_AGENT, DEFAULT_MODERATOR_AGENT, DEFAULT_NEGATIVE_AGENT
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


@dataclass
class SideConclusion:
    label: str
    verdict: Verdict
    statement: str


class DebateOrchestrator:
    def __init__(
        self,
        max_rounds: int = 4,
        llm_client: Optional[LLMClient] = None,
        affirmative_client: Optional[LLMClient] = None,
        negative_client: Optional[LLMClient] = None,
        moderator_client: Optional[LLMClient] = None,
        affirmative_agent: Optional[AgentConfig] = None,
        negative_agent: Optional[AgentConfig] = None,
        moderator_agent: Optional[AgentConfig] = None,
        progress_callback: Optional[Callable[[VerdictReport], None]] = None,
    ):
        self.max_rounds = max_rounds
        self.affirmative_client = affirmative_client or llm_client
        self.negative_client = negative_client or llm_client
        self.moderator_client = moderator_client or llm_client
        self.affirmative_agent = _agent_or_default(affirmative_agent, DEFAULT_AFFIRMATIVE_AGENT)
        self.negative_agent = _agent_or_default(negative_agent, DEFAULT_NEGATIVE_AGENT)
        self.moderator_agent = _agent_or_default(moderator_agent, DEFAULT_MODERATOR_AGENT)
        self.progress_callback = progress_callback

    def adjudicate(self, bundle: EvidenceBundle) -> VerdictReport:
        evidence = bundle.evidence
        decision = self._decide(bundle)
        turns, final_conclusion, decision = self._debate_turns(bundle, decision)
        return VerdictReport(
            finding_id=bundle.finding.finding_id,
            rule_id=bundle.finding.rule_id,
            verdict=decision.verdict,
            confidence=round(decision.confidence, 2),
            reasoning_summary=decision.reasoning_summary,
            final_conclusion=final_conclusion,
            evidence_chain=evidence,
            debate=turns,
            disputed_points=decision.disputed_points,
            protection_assessment=_protection_assessment(evidence),
            impact_assessment=_impact_assessment(evidence),
            source_locations=_resolved_source_locations(evidence, bundle.finding.locations),
            recommended_next_steps=decision.recommended_next_steps,
        )

    def _debate_turns(
        self, bundle: EvidenceBundle, base_decision: DebateDecision
    ) -> Tuple[List[DebateTurn], str, DebateDecision]:
        evidence = bundle.evidence
        challenges = self._challenges(bundle)
        source_root_ids = _ids(evidence, EvidenceKind.SOURCE_ROOT)
        report_ids = _ids(evidence, EvidenceKind.REPORT)
        location_ids = _ids(evidence, EvidenceKind.SOURCE_LOCATION)
        flow_ids = _ids(evidence, EvidenceKind.SARIF_CODE_FLOW, EvidenceKind.DATA_FLOW, EvidenceKind.CALL_CHAIN)
        protection_ids = _ids(evidence, EvidenceKind.PROTECTION)
        impact_ids = _ids(evidence, EvidenceKind.IMPACT, EvidenceKind.PROJECT_CONTEXT)
        tool_diag_ids = _ids(evidence, EvidenceKind.TOOL_DIAGNOSTIC)
        affirmative_report = self._llm_claim(
            "AFFIRMATIVE",
            (
                "提交完整正方证据报告。目标固定为：证明报告发现能否由外部接口或内部接口调用触发，"
                "给出准确函数调用链、源到汇数据流、攻击链、攻击前提、直接影响和必要限制。"
                "所有 Atlas、rg/grep 和源码阅读都必须围绕报告位置、报告符号、codeFlow 或其调用邻域验证，不得用全项目无关命中混充证据。"
                "调用链分析必须优先使用 Atlas search/trace/calls 向上游追溯，直到到达外部输入源头（用户输入、文件输入、网络报文输入、命令行参数、标准输入、请求参数或消息队列载荷等）。"
                "当 Atlas 无法继续追溯、trace partial/empty/No data node、calls 缺边、search 未命中或疑似无法解析间接调用时，不得直接判为证据不足或误报；"
                "应合理怀疑 Atlas 未正确处理调用链关系，转用源码阅读和 grep/ripgrep 围绕报告路径、符号、调用邻域、入口函数名、参数名、源点词和汇点词补证。"
                "一旦源码阅读或 grep/ripgrep 找到当前调用链、上游调用者或数据流节点，必须转回 Atlas 对新发现上游符号继续追溯。"
                "只有 Atlas、源码阅读、grep/ripgrep 与交叉验证均失败时，才可怀疑报告为误报、不可利用漏洞或证据不足。"
                "如有证据缺口，应主动从已有证据中交叉验证补强（如从 calls 调用图反查数据流、从源码片段拼接路径、用报告附近符号补全 search 遗漏），"
                "只有在穷尽补强手段后才可标注为证据限制，并说明尝试过哪些补强方法。"
                "防护消减只在源码或 Skill/项目上下文存在明确防护证据时分析；没有证据就不要引入防护消减假设。"
            ),
            bundle,
            extra=_stage_context(
                "正方第一回合",
                (
                    "优先使用 Atlas MCP 证据向上游追溯到外部输入源头。若证据显示 Atlas 数据库缺失，才可说明需要执行 "
                    "`atlas index --analysis full`；若证据显示 Atlas MCP 已返回 project/status、project/files、trace 或 calls，"
                    "必须引用这些证据判断源码真实性、调用图和数据流。Atlas 缺边、未命中或 trace 不完整时，先合理怀疑工具未正确处理调用链，"
                    "转用源码阅读和 grep/ripgrep 定位调用链或数据流；找到新上游节点后再回到 Atlas 继续追溯。只有这些路径均失败时，"
                    "才可怀疑误报、不可利用漏洞或证据不足。不得说 .atlas 缺失或未构建，除非证据明确显示数据库缺失。"
                ),
                challenges,
                _affirmative_evidence_hunting_context(bundle),
            ),
        ) or _affirmative_evidence_report(bundle, base_decision, challenges)
        turns: List[DebateTurn] = []
        turns.append(
            DebateTurn(
                role=DebateRole.AFFIRMATIVE,
                round_index=1,
                claim=affirmative_report,
                evidence_ids=source_root_ids + report_ids + location_ids + flow_ids + impact_ids,
            )
        )
        self._emit_progress(bundle, base_decision, turns)
        negative_report = self._llm_claim(
            "NEGATIVE",
            (
                "提交反方质疑报告。目标固定为：客观验证正方给出的报告源码真实性、外部/内部入口可达性、"
                "调用链、源到汇数据流、攻击影响和防护分析是否由证据支持。重点找出证据跳跃、无关 rg/Atlas 命中、"
                "把候选汇点当作可达汇点、遗漏调用前提或浑水摸鱼的地方。只能引用提示中给出的证据 ID。"
                "防护消减只能基于源码或 Skill/项目上下文中的明确防护证据质疑；没有证据时不得凭空假设统一防护。"
            ),
            bundle,
            extra=_stage_context("反方第一回合", "正方证据报告：\n" + affirmative_report, challenges, ""),
        ) or _negative_challenge_report(bundle, challenges, affirmative_report)
        turns.append(
            DebateTurn(
                role=DebateRole.NEGATIVE,
                round_index=1,
                claim=negative_report,
                evidence_ids=source_root_ids + protection_ids + tool_diag_ids,
                resolved=not challenges,
            )
        )
        self._emit_progress(bundle, base_decision, turns)
        if repetition_issue := _moderator_repetition_issue(turns):
            return self._early_moderator_conclusion(bundle, base_decision, challenges, turns, repetition_issue)
        unresolved = list(challenges)
        last_negative = negative_report
        for round_index in range(2, max(1, self.max_rounds) + 1):
            if not unresolved:
                break
            clarification = self._llm_claim(
                "AFFIRMATIVE",
                (
                    "逐项回应反方质疑。每个质疑点都要给出：可被证据支持的澄清、用交叉验证补强的论证、仍未闭环的限制。"
                    "不要直接承认证据不足——先用 Atlas 向上游追到外部输入源头；Atlas 无法推进时，转用源码阅读和 grep/ripgrep 搜索调用邻域、入口函数、源点词和汇点词。"
                    "如果源码阅读或 grep/ripgrep 找到新的上游调用者或数据流节点，必须回到 Atlas 对该节点继续追溯。"
                    "只有当 Atlas、源码阅读、grep/ripgrep 和交叉验证均无法闭合时，才明确说明尝试过的手段及剩余缺口，并考虑误报或不可利用。"
                    "对攻击链/前提/影响结论如有修正必须给出新的证据引用。"
                ),
                bundle,
                extra=_stage_context(
                    f"正方第 {round_index} 回合澄清",
                    "上一轮反方质疑：\n" + last_negative,
                    unresolved,
                    _affirmative_evidence_hunting_context(bundle),
                ),
            ) or _affirmative_clarification_report(bundle, unresolved, round_index)
            answer_ids = source_root_ids + location_ids + flow_ids + protection_ids + impact_ids
            turns.append(
                DebateTurn(
                    role=DebateRole.AFFIRMATIVE,
                    round_index=round_index,
                    claim=clarification,
                    evidence_ids=answer_ids,
                    resolved=not _material_unresolved(challenges),
                )
            )
            self._emit_progress(bundle, base_decision, turns)
            if repetition_issue := _moderator_repetition_issue(turns):
                return self._early_moderator_conclusion(bundle, base_decision, challenges, turns, repetition_issue)
            negative_review = self._llm_claim(
                "NEGATIVE",
                (
                    "复审正方澄清。指出已经闭环的问题和仍然不成立的断点，并给出是否继续质疑。"
                    "重点仍是攻击链真实性、攻击前提、防护消减和影响归因。"
                ),
                bundle,
                extra=_stage_context(
                    f"反方第 {round_index} 回合复审",
                    "正方澄清：\n" + clarification,
                    unresolved,
                    "",
                ),
            ) or _negative_review_report(bundle, unresolved, clarification, round_index)
            turns.append(
                DebateTurn(
                    role=DebateRole.NEGATIVE,
                    round_index=round_index,
                    claim=negative_review,
                    evidence_ids=protection_ids + tool_diag_ids + flow_ids + location_ids,
                    resolved=not _material_unresolved(unresolved),
                )
            )
            self._emit_progress(bundle, base_decision, turns)
            if repetition_issue := _moderator_repetition_issue(turns):
                return self._early_moderator_conclusion(bundle, base_decision, challenges, turns, repetition_issue)
            last_negative = negative_review
            if _can_reach_consensus(base_decision, unresolved):
                unresolved = []

        final_round = max((turn.round_index for turn in turns), default=0) + 1
        affirmative_final = self._side_conclusion("AFFIRMATIVE", bundle, base_decision, challenges, last_negative)
        turns.append(
            DebateTurn(
                role=DebateRole.AFFIRMATIVE,
                round_index=final_round,
                claim=f"## 正方结案\n【{affirmative_final.label}】，{affirmative_final.statement}",
                evidence_ids=source_root_ids + report_ids + location_ids + flow_ids + impact_ids,
                resolved=True,
            )
        )
        self._emit_progress(bundle, base_decision, turns)
        negative_final = self._side_conclusion("NEGATIVE", bundle, base_decision, challenges, last_negative)
        side_final_conclusion = _final_conclusion(affirmative_final, negative_final)
        moderator_summary = self._moderator_summary(
            bundle,
            base_decision,
            challenges,
            affirmative_final,
            negative_final,
            side_final_conclusion,
            turns,
        )
        final_conclusion = moderator_summary or side_final_conclusion
        decision = _decision_from_conclusions(base_decision, affirmative_final, negative_final, final_conclusion)
        turns.append(
            DebateTurn(
                role=DebateRole.NEGATIVE,
                round_index=final_round,
                claim=f"## 反方结案\n【{negative_final.label}】，{negative_final.statement}",
                evidence_ids=source_root_ids + protection_ids + tool_diag_ids + location_ids + flow_ids,
                resolved=True,
            )
        )
        self._emit_progress(bundle, decision, turns)
        turns.append(
            DebateTurn(
                role=DebateRole.MODERATOR,
                round_index=final_round,
                claim=final_conclusion,
                evidence_ids=[item.evidence_id for item in evidence],
                resolved=decision.verdict != Verdict.INCONCLUSIVE,
            )
        )
        self._emit_progress(bundle, decision, turns, final_conclusion=final_conclusion)
        return turns, final_conclusion, decision

    def _early_moderator_conclusion(
        self,
        bundle: EvidenceBundle,
        base_decision: DebateDecision,
        challenges: Sequence[str],
        turns: List[DebateTurn],
        reason: str,
    ) -> Tuple[List[DebateTurn], str, DebateDecision]:
        affirmative_label, affirmative_verdict, affirmative_statement = _fallback_side_conclusion(
            "AFFIRMATIVE", bundle, base_decision, challenges
        )
        negative_label, negative_verdict, negative_statement = _fallback_side_conclusion(
            "NEGATIVE", bundle, base_decision, challenges
        )
        affirmative = SideConclusion(affirmative_label, affirmative_verdict, affirmative_statement)
        negative = SideConclusion(negative_label, negative_verdict, negative_statement)
        side_final = _final_conclusion(affirmative, negative)
        final_conclusion = f"Moderator 提前结束：{reason}；{side_final}"
        decision = _decision_from_conclusions(base_decision, affirmative, negative, final_conclusion)
        turns.append(
            DebateTurn(
                role=DebateRole.MODERATOR,
                round_index=max((turn.round_index for turn in turns), default=0),
                claim=final_conclusion,
                evidence_ids=[item.evidence_id for item in bundle.evidence],
                resolved=decision.verdict != Verdict.INCONCLUSIVE,
            )
        )
        self._emit_progress(bundle, decision, turns, final_conclusion=final_conclusion)
        return turns, final_conclusion, decision

    def _emit_progress(
        self,
        bundle: EvidenceBundle,
        decision: DebateDecision,
        turns: Sequence[DebateTurn],
        final_conclusion: str = "",
    ) -> None:
        if self.progress_callback is None:
            return
        self.progress_callback(
            VerdictReport(
                finding_id=bundle.finding.finding_id,
                rule_id=bundle.finding.rule_id,
                verdict=decision.verdict,
                confidence=round(decision.confidence, 2),
                reasoning_summary=decision.reasoning_summary,
                final_conclusion=final_conclusion,
                evidence_chain=bundle.evidence,
                debate=list(turns),
                disputed_points=decision.disputed_points,
                protection_assessment=_protection_assessment(bundle.evidence),
                impact_assessment=_impact_assessment(bundle.evidence),
                source_locations=_resolved_source_locations(bundle.evidence, bundle.finding.locations),
                recommended_next_steps=decision.recommended_next_steps,
            )
        )

    def _challenges(self, bundle: EvidenceBundle) -> List[str]:
        evidence = bundle.evidence
        challenges: List[str] = []
        if _all_primary_locations_invalid(evidence):
            challenges.append("报告位置无法在提供的源码树中解析。")
        if not _has_meaningful_flow(evidence):
            challenges.append("尚未建立已验证的源到汇数据流或调用路径。")
        if _has_protection(evidence):
            challenges.append("附近代码存在可能缓解问题的校验、鉴权或消毒逻辑。")
        if not _has_impact(evidence):
            challenges.append("实际影响尚未关联到资产、权限或可达的危险汇点。")
        challenges.extend(bundle.diagnostics)
        return challenges

    def _llm_claim(self, role: str, task: str, bundle: EvidenceBundle, extra: str) -> Optional[str]:
        return self._llm_response(role, task, bundle, extra, "请用中文写一个可审计的辩论回合，不要使用 Markdown 表格。")

    def _llm_response(
        self, role: str, task: str, bundle: EvidenceBundle, extra: str, output_instruction: str
    ) -> Optional[str]:
        client = self._client_for_role(role)
        if client is None:
            return None
        agent = self._agent_for_role(role)
        role_label = _role_label(role)
        agent_name = agent.name.strip() or role_label
        agent_instructions = agent.instructions.strip()
        system = (
            f"你是 {agent_name}，在静态漏洞研判博弈中担任{role_label}。"
            "禁止编造文件、数据流、防护措施或漏洞影响。"
            "每个具体论断都必须引用提示中一个或多个证据 ID。"
            "输出必须使用中文 Markdown。"
        )
        if agent_instructions:
            system += f"\n角色配置：\n{agent_instructions}"
        user = (
            f"任务：{task}\n"
            f"发现：{bundle.finding.rule_id} - {bundle.finding.message}\n"
            f"证据：\n" + _evidence_prompt(bundle.evidence) + "\n"
            "证据解释约束：SOURCE_ROOT 只能证明任务已配置源码根目录，不能替代具体 SOURCE_LOCATION、CALL_CHAIN 或 DATA_FLOW；"
            "rg/grep 证据必须围绕报告位置、报告符号、codeFlow 或调用邻域解释，只能作为候选补证，不能单独证明源汇可达；"
            "若存在 atlas-agent-mcp 证据，应优先按 MCP 的 project/status、project/files、trace、calls 结果研判；"
            "若 Atlas 数据库存在但 trace 结果为 empty/partial/No data node，应转而从 calls 调用图和源码片段交叉验证重构数据流；"
            "若 Atlas 数据库存在但 trace_supported=false，只能说明当前工具无法导出 trace，不得说 .atlas 缺失或未构建。\n"
            f"补充上下文或质疑：\n{extra}\n"
            f"{output_instruction}"
        )
        return client.complete(system, user)

    def _client_for_role(self, role: str) -> Optional[LLMClient]:
        if role == "AFFIRMATIVE":
            return self.affirmative_client
        if role == "NEGATIVE":
            return self.negative_client
        return self.moderator_client

    def _agent_for_role(self, role: str) -> AgentConfig:
        if role == "AFFIRMATIVE":
            return self.affirmative_agent
        if role == "NEGATIVE":
            return self.negative_agent
        return self.moderator_agent

    def _affirmative_reply(self, bundle: EvidenceBundle, challenges: Sequence[str]) -> str:
        evidence = bundle.evidence
        replies = []
        if _has_valid_location(evidence):
            replies.append("SARIF 位置可以解析到真实源码，源码片段已提供上下文。")
        if _has_meaningful_flow(evidence):
            replies.append("分析器提供了调用链/数据流证据，可从调用方-被调用方重构攻击路径。")
        else:
            replies.append("虽无直接数据流证据，但应尝试从调用图、源码片段和符号交叉引用手动拼接路径。")
        if _has_protection(evidence):
            replies.append("存在防护证据，需结合源码片段分析其实际有效性，不可直接假定能完全消减风险。")
        if _has_impact(evidence):
            replies.append("影响已从规则/消息和项目上下文映射，可结合调用链进一步归因到具体汇点。")
        return " ".join(replies)

    def _side_conclusion(
        self,
        role: str,
        bundle: EvidenceBundle,
        decision: DebateDecision,
        challenges: Sequence[str],
        last_negative: str,
    ) -> SideConclusion:
        label, verdict, statement = _fallback_side_conclusion(role, bundle, decision, challenges)
        llm_statement = self._llm_response(
            role,
            (
                f"给出简短结案陈述。结论标签已固定为【{label}】，不得改成其他标签。"
                "只输出结案陈述正文 1 到 3 句话，不要输出 Markdown 表格，不要复述用户要求、任务要求、角色名称或格式说明。"
            ),
            bundle,
            extra=_stage_context("结案", "最近一轮反方意见：\n" + last_negative, challenges, ""),
            output_instruction="只返回结案陈述正文 1 到 3 句话；不要说明你要做什么，不要复述任务、标签或格式要求。",
        )
        if llm_statement:
            statement = _clean_final_statement(llm_statement, label) or statement
        return SideConclusion(label=label, verdict=verdict, statement=statement)

    def _moderator_summary(
        self,
        bundle: EvidenceBundle,
        decision: DebateDecision,
        challenges: Sequence[str],
        affirmative_final: SideConclusion,
        negative_final: SideConclusion,
        side_final_conclusion: str,
        turns: Sequence[DebateTurn],
    ) -> Optional[str]:
        turn_context = "\n\n".join(
            f"{_role_label(turn.role.value)}第 {turn.round_index} 回合：\n{turn.claim}" for turn in turns[-6:]
        )
        llm_summary = self._llm_response(
            "MODERATOR",
            (
                "作为中立 Moderator，总结正反方核心观点、双方一致点、主要分歧、证据闭环状态和最终研判。"
                "不得新增证据链之外的新事实；不得替任一方辩护；只基于双方陈述和证据 ID 做客观归纳。"
                "输出 2 到 5 句话，不要使用 Markdown 表格。"
            ),
            bundle,
            extra=_stage_context(
                "主持人总结",
                (
                    f"正方结案：【{affirmative_final.label}】，{affirmative_final.statement}\n"
                    f"反方结案：【{negative_final.label}】，{negative_final.statement}\n"
                    f"自动裁决摘要：{decision.reasoning_summary}\n"
                    f"当前合成结论：{side_final_conclusion}\n"
                    f"最近回合：\n{turn_context}"
                ),
                challenges,
                "",
            ),
            output_instruction="只返回主持人总结正文 2 到 5 句话；不要说明你要做什么，不要复述任务、标签或格式要求。",
        )
        if not llm_summary:
            return None
        return _clean_moderator_summary(llm_summary)

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


def _affirmative_evidence_report(
    bundle: EvidenceBundle, decision: DebateDecision, challenges: Sequence[str]
) -> str:
    evidence = bundle.evidence
    return "\n".join(
        [
            "## 正方证据报告",
            "### 1. 输入报告证据",
            _evidence_bullets(evidence, {EvidenceKind.REPORT}) or "未找到输入报告证据。",
            "### 2. 源码真实性",
            _source_authenticity_report(evidence),
            "### 3. 函数调用链与数据流",
            _flow_report(evidence),
            "### 4. 攻击链",
            _attack_chain_report(bundle),
            "### 5. 攻击前提与限制",
            _attack_prerequisite_report(evidence, challenges),
            "### 6. 防护消减分析",
            _protection_assessment(evidence),
            "### 7. 攻击影响",
            _impact_assessment(evidence),
            "### 8. PoC/EXP",
            _poc_report(evidence),
            "### 9. 正方补证策略",
            _affirmative_evidence_hunting_report(evidence),
            "### 正方阶段性结论",
            f"{decision.reasoning_summary} 当前启发式标签倾向：{_verdict_label(decision.verdict)}。",
        ]
    )


def _negative_challenge_report(bundle: EvidenceBundle, challenges: Sequence[str], affirmative_report: str) -> str:
    evidence = bundle.evidence
    challenge_text = "\n".join(f"- {item}" for item in challenges) if challenges else "- 暂未发现足以推翻主张的硬性反证。"
    return "\n".join(
        [
            "## 反方质疑报告",
            "### 1. 攻击链路真实性",
            _negative_chain_challenge(evidence),
            "### 2. 调用链与数据流交叉验证",
            _negative_flow_challenge(evidence),
            "### 3. 攻击前提是否过高",
            _negative_prerequisite_challenge(evidence, challenges),
            "### 4. 安全防护消减风险",
            _negative_protection_challenge(evidence),
            "### 5. 攻击影响是否被夸大",
            _negative_impact_challenge(evidence),
            "### 6. 待正方澄清的问题",
            challenge_text,
            "### 反方阶段性意见",
            "正方必须证明报告位置、源码片段、调用链/数据流和影响归因均能闭环；否则结论应降级为误报或证据不足。",
        ]
    )


def _affirmative_clarification_report(
    bundle: EvidenceBundle, challenges: Sequence[str], round_index: int
) -> str:
    if not challenges:
        clarification = "- 反方未提出实质性质疑，正方维持原证据报告。"
    else:
        clarification = "\n".join(f"- 质疑：{item}\n  澄清：{_clarification_for_challenge(bundle.evidence, item)}" for item in challenges)
    return "\n".join(
        [
            f"## 正方第 {round_index} 回合澄清报告",
            "### 逐项澄清",
            clarification,
            "### 结论修正",
            _affirmative_reply_static(bundle, challenges),
        ]
    )


def _negative_review_report(
    bundle: EvidenceBundle, challenges: Sequence[str], clarification: str, round_index: int
) -> str:
    unresolved = [item for item in challenges if _challenge_still_material(bundle.evidence, item)]
    unresolved_text = (
        "\n".join(f"- {item}" for item in unresolved)
        if unresolved
        else "- 当前自动化证据中未保留足以继续阻断结论的实质性质疑。"
    )
    return "\n".join(
        [
            f"## 反方第 {round_index} 回合复审报告",
            "### 已复审的正方澄清",
            "正方澄清已按证据链重新检查；反方不接受未引用证据 ID 的新增事实。",
            "### 仍未闭环的问题",
            unresolved_text,
            "### 反方复审意见",
            _negative_review_summary(bundle.evidence, unresolved),
        ]
    )


def _stage_context(stage: str, prior: str, challenges: Sequence[str], extra: str) -> str:
    challenge_text = "\n".join(f"- {item}" for item in challenges) if challenges else "- 暂无已知阻断性质疑。"
    parts = [f"阶段：{stage}", f"已知质疑：\n{challenge_text}"]
    if prior:
        parts.append(prior)
    if extra:
        parts.append(extra)
    return "\n\n".join(parts)


def _evidence_prompt(evidence: Sequence[CodeEvidence]) -> str:
    lines: List[str] = []
    snippet_count = 0
    for item in evidence[:30]:
        lines.append(
            f"- {item.evidence_id} | {_evidence_kind_label(item.kind)}（{item.kind.value}） | "
            f"{_evidence_strength_label(item.strength)}（{item.strength.value}） | 来源：{item.source} | {item.summary}"
        )
        if item.locations:
            lines.append("  位置：" + " -> ".join(location.display() for location in item.locations[:8]))
        if item.snippet and snippet_count < 8:
            lines.append("  代码片段：\n```text\n" + item.snippet[:1200] + "\n```")
            snippet_count += 1
        data_excerpt = _data_excerpt(item)
        if data_excerpt:
            lines.append("  数据：" + data_excerpt)
    if len(evidence) > 30:
        lines.append(f"- 另有 {len(evidence) - 30} 条证据未展开。")
    return "\n".join(lines) if lines else "无证据。"


def _data_excerpt(item: CodeEvidence) -> str:
    keys = (
        "source_root",
        "source_root_exists",
        "source_root_is_dir",
        "languages",
        "atlas_database",
        "atlas_database_exists",
        "transport",
        "mcp_tool",
        "trace_kind",
        "trace_file",
        "trace_line",
        "trace_column",
        "ok",
        "partial_result",
        "truncated_json",
        "diagnostics",
        "query_id",
        "callers",
        "callees",
        "symbols",
        "source_terms",
        "sink_terms",
        "search_scope",
        "scoped_paths",
        "query_terms",
        "terms",
        "impacts",
        "code_flow_count",
        "missing_evidence",
        "suggested_actions",
        "atlas_mode",
        "auto_index_tools",
        "indexed_files",
        "indexed_file_count",
        "files_indexed",
        "language_level",
        "trace_supported",
        "requested_file",
        "resolved_file",
        "result",
    )
    pairs = []
    for key in keys:
        if key in item.data and item.data.get(key) not in (None, "", [], {}):
            pairs.append(f"{key}={item.data.get(key)}")
    return "; ".join(pairs)[:500]


def _evidence_bullets(
    evidence: Sequence[CodeEvidence], kinds: Optional[set[EvidenceKind]] = None, limit: int = 8
) -> str:
    selected = [item for item in evidence if kinds is None or item.kind in kinds]
    bullets = []
    for item in selected[:limit]:
        location_text = ""
        if item.locations:
            location_text = "（" + " -> ".join(location.display() for location in item.locations[:5]) + "）"
        bullets.append(f"- `{item.evidence_id}` {item.summary}{location_text}")
    if len(selected) > limit:
        bullets.append(f"- 另有 {len(selected) - limit} 条同类证据未展开。")
    return "\n".join(bullets)


def _flow_report(evidence: Sequence[CodeEvidence]) -> str:
    flow_items = [
        item
        for item in evidence
        if item.kind in {EvidenceKind.SARIF_CODE_FLOW, EvidenceKind.DATA_FLOW, EvidenceKind.CALL_CHAIN}
    ]
    lines = []
    atlas_items = [item for item in evidence if _is_atlas_source(item)]
    if atlas_items:
        lines.append("- Atlas 证据：" + "; ".join(f"`{item.evidence_id}` {item.summary}" for item in atlas_items[:4]))
        if _has_atlas_trace_unavailable(evidence):
            lines.append("- Atlas 数据库/索引存在，但当前 CLI 未提供 trace 子命令，因此只能作为索引覆盖证据，不能作为数据流 trace。")
    else:
        lines.append("- 未获得 Atlas 证据；需要确认是否已安装 Atlas 并完成 `atlas index --analysis full`。")
    if not flow_items:
        lines.append("- 当前未建立源到汇数据流或函数调用链证据。")
        return "\n".join(lines)
    for item in flow_items[:8]:
        locations = " -> ".join(location.display() for location in item.locations[:10]) if item.locations else "未展开位置"
        symbols = item.data.get("symbols") or []
        symbol_text = f"，符号：{', '.join(symbols)}" if symbols else ""
        lines.append(f"- `{item.evidence_id}` {item.summary}；路径：{locations}{symbol_text}")
    return "\n".join(lines)


def _source_authenticity_report(evidence: Sequence[CodeEvidence]) -> str:
    root_text = _evidence_bullets(evidence, {EvidenceKind.SOURCE_ROOT}) or "未看到任务源码根目录证据。"
    location_text = _evidence_bullets(evidence, {EvidenceKind.SOURCE_LOCATION}) or "报告未提供可解析到源码的具体文件/行号。"
    return root_text + "\n" + location_text


def _attack_chain_report(bundle: EvidenceBundle) -> str:
    evidence = bundle.evidence
    steps = [
        f"1. 报告入口：`{bundle.finding.rule_id}` 指出 {bundle.finding.message}，对应输入报告证据 {_join_ids(_ids(evidence, EvidenceKind.REPORT))}。",
        "2. 源码定位：" + (_source_authenticity_report(evidence).replace("\n", "\n   ") or "未能定位真实源码。"),
        "3. 传播/调用路径：" + (_flow_report(evidence).replace("\n", "\n   ") or "未建立路径。"),
        "4. 危险操作或资产影响：" + _impact_assessment(evidence),
    ]
    if _has_protection(evidence):
        steps.append("5. 防护限制：路径附近存在防护证据，攻击链必须证明这些控制无法覆盖该输入。")
    else:
        steps.append("5. 防护限制：未发现针对报告路径的防护消减证据，本轮不引入防护消减假设。")
    return "\n".join(steps)


def _attack_prerequisite_report(evidence: Sequence[CodeEvidence], challenges: Sequence[str]) -> str:
    lines = [
        "- 攻击者需要能够触发报告中的入口或向相关接口/参数提供输入。",
        "- 需要源码定位和数据流/调用链证据能证明该输入到达危险汇点。",
    ]
    if _has_protection(evidence):
        lines.append("- 若存在鉴权、校验、消毒、限流或策略控制，攻击者还需要满足或绕过这些控制。")
    if _material_unresolved(challenges):
        lines.append("- 当前仍存在阻断性质疑，攻击前提不能被视为完全闭环。")
    return "\n".join(lines)


def _poc_report(evidence: Sequence[CodeEvidence]) -> str:
    if _has_meaningful_flow(evidence) and not _has_protection(evidence):
        return "证据支持生成最小验证用例，但当前自动流程不生成可执行 EXP；建议在授权测试环境中基于入口参数构造最小非破坏性 PoC。"
    return "证据尚不足以安全生成 PoC/EXP；应先补齐可达入口、数据流和防护有效性验证。"


def _affirmative_evidence_hunting_context(bundle: EvidenceBundle) -> str:
    plans = _affirmative_evidence_plans(bundle.evidence)
    if not plans:
        return "正方证据不足补强策略：当前自动证据未生成额外补证计划；仍需优先进行源码分析、Atlas 检查和交叉验证路径。"
    lines = ["正方证据不足补强策略：证据不足时不得直接停止，应先按以下补证计划寻找新证据。"]
    for item in plans[:3]:
        lines.append(f"- 引用 `{item.evidence_id}`：{item.summary}")
        for action in (item.data.get("suggested_actions") or [])[:5]:
            lines.append(f"  - {action}")
    lines.append(
        "执行要求：优先补充 SOURCE_LOCATION、DATA_FLOW、CALL_CHAIN 和 TOOL_DIAGNOSTIC 证据引用；"
        "调用链应先用 Atlas 追到外部输入源头，Atlas 无法推进时转用源码分析和 grep/ripgrep，"
        "找到新上游节点后再回到 Atlas 继续追溯；如果仍失败，必须说明已尝试的源码分析、Atlas 检查和交叉验证路径。"
    )
    return "\n".join(lines)


def _affirmative_evidence_hunting_report(evidence: Sequence[CodeEvidence]) -> str:
    plans = _affirmative_evidence_plans(evidence)
    if not plans:
        return "当前自动证据未生成额外补证计划；正方仍应优先交叉验证源码位置、调用链、数据流和影响归因。"
    lines = []
    for item in plans[:3]:
        missing = item.data.get("missing_evidence") or []
        lines.append(f"- `{item.evidence_id}` {item.summary}")
        if missing:
            lines.append("  缺口：" + ", ".join(str(value) for value in missing))
        for action in (item.data.get("suggested_actions") or [])[:6]:
            lines.append(f"  - {action}")
    return "\n".join(lines)


def _affirmative_evidence_plans(evidence: Sequence[CodeEvidence]) -> List[CodeEvidence]:
    return [item for item in evidence if item.source == "affirmative-evidence-planner"]


def _negative_chain_challenge(evidence: Sequence[CodeEvidence]) -> str:
    if _all_primary_locations_invalid(evidence):
        return "报告中的主位置无法在源码树中解析，攻击链从第一步开始不成立。"
    if not _has_valid_location(evidence):
        if _has_source_root(evidence):
            return "任务源码根目录已配置，但尚未确认该发现对应的具体源码片段，需防止 SARIF/Markdown 报告缺少位置或与源码版本不一致。"
        return "尚未确认报告位置对应真实源码片段，需防止 SARIF/Markdown 报告与源码版本不一致。"
    return "源码位置存在，但仍需确认这些位置处于真实可调用路径，而非死代码或测试代码。"


def _negative_flow_challenge(evidence: Sequence[CodeEvidence]) -> str:
    if _has_meaningful_flow(evidence):
        return "已存在较强路径/数据流证据；反方仍需检查每个步骤是否同版本、同函数上下文且无跳跃断点。"
    return "未看到已验证的端到端调用链或源到汇数据流，不能只凭单行危险 API 推断真实漏洞。"


def _negative_prerequisite_challenge(evidence: Sequence[CodeEvidence], challenges: Sequence[str]) -> str:
    if _material_unresolved(challenges):
        return "攻击前提仍依赖未闭环的路径或工具证据，真实场景中可能不存在可触发入口。"
    return "攻击前提看起来不过分，但仍要确认外部接口、认证态、租户边界和输入可控性。"


def _negative_protection_challenge(evidence: Sequence[CodeEvidence]) -> str:
    if _has_protection(evidence):
        return "源码附近存在可能的鉴权、校验、消毒或限流证据，正方必须证明这些控制无法消减该风险。"
    return "当前证据未发现针对报告路径的防护消减证据；反方不得凭空引入统一防护，只能指出正方未提交相关防护证据。"


def _negative_impact_challenge(evidence: Sequence[CodeEvidence]) -> str:
    impacts = [item for item in evidence if item.kind in {EvidenceKind.IMPACT, EvidenceKind.PROJECT_CONTEXT}]
    if not impacts:
        return "未看到价值资产、权限边界或业务影响证据，不能扩大影响。"
    return "影响只能归因于漏洞技术路径本身；不得把社会工程、凭证窃取后的横向移动等后续非直接路径计入直接影响。"


def _clarification_for_challenge(evidence: Sequence[CodeEvidence], challenge: str) -> str:
    if "源码" in challenge or "位置" in challenge or "解析" in challenge:
        return "源码真实性依据为：" + _source_authenticity_report(evidence)
    if "数据流" in challenge or "调用" in challenge or "路径" in challenge:
        return _flow_report(evidence)
    if "防护" in challenge or "校验" in challenge or "鉴权" in challenge or "消毒" in challenge:
        return _protection_assessment(evidence)
    if "影响" in challenge or "资产" in challenge:
        return _impact_assessment(evidence)
    return "该质疑需要人工复核；当前自动证据不能新增未采集事实，但可从已有调用图、源码片段和符号引用中交叉验证。"


def _affirmative_reply_static(bundle: EvidenceBundle, challenges: Sequence[str]) -> str:
    evidence = bundle.evidence
    replies = []
    if _has_valid_location(evidence):
        replies.append("源码位置已被确认存在，源码片段可交叉验证。")
    if _has_meaningful_flow(evidence):
        replies.append("已存在调用链/数据流证据，可从调用方-被调用方重构完整攻击路径。")
    else:
        replies.append("虽无直接数据流，但应尝试从调用图、源码片段和符号交叉引用手动拼接路径，而非直接降低结论强度。")
    if _has_protection(evidence):
        replies.append("存在防护迹象，需结合源码片段分析其实际有效性；若防护不足，风险仍可成立。")
    if _has_impact(evidence):
        replies.append("影响分析可从证据链中的调用链和项目上下文中进一步归因到具体汇点。")
    return " ".join(replies)


def _challenge_still_material(evidence: Sequence[CodeEvidence], challenge: str) -> bool:
    if "无法" in challenge or "位置" in challenge:
        return not _has_valid_location(evidence)
    if "数据流" in challenge or "调用" in challenge or "路径" in challenge or "尚未建立" in challenge:
        return not _has_meaningful_flow(evidence)
    if "防护" in challenge:
        return _has_protection(evidence)
    if "影响" in challenge:
        return not _has_impact(evidence)
    return _material_unresolved([challenge])


def _negative_review_summary(evidence: Sequence[CodeEvidence], unresolved: Sequence[str]) -> str:
    if unresolved:
        return "仍存在影响结论成立的断点，反方暂不接受正方完全成立的漏洞结论。"
    if _has_meaningful_flow(evidence) and not _has_protection(evidence):
        return "在当前证据下，反方接受攻击链基本成立，但保留对业务前提的人工复核要求。"
    return "正方澄清降低了部分不确定性，但自动证据仍不足以直接定性。"


def _moderator_repetition_issue(turns: Sequence[DebateTurn]) -> Optional[str]:
    if len(turns) < 2:
        return None
    latest = turns[-1]
    if latest.role == DebateRole.MODERATOR:
        return None
    latest_text = _normalize_claim_for_repetition(latest.claim)
    if len(latest_text) < 24:
        return None
    for previous in turns[:-1]:
        if previous.role == DebateRole.MODERATOR:
            continue
        previous_text = _normalize_claim_for_repetition(previous.claim)
        if len(previous_text) < 24:
            continue
        similarity = difflib.SequenceMatcher(None, latest_text, previous_text).ratio()
        same_role_threshold = 0.88 if latest.role == previous.role else 0.94
        contains_repetition = (
            latest.role == previous.role
            and min(len(latest_text), len(previous_text)) >= 80
            and (latest_text in previous_text or previous_text in latest_text)
        )
        if similarity >= same_role_threshold or contains_repetition:
            return (
                f"检测到{_role_label(latest.role.value)}第 {latest.round_index} 回合与"
                f"{_role_label(previous.role.value)}第 {previous.round_index} 回合高度复读，"
                "继续辩论不会增加新证据"
            )
    return None


def _normalize_claim_for_repetition(text: str) -> str:
    normalized = re.sub(r"`[^`]+`", "", text.lower())
    normalized = re.sub(r"\b[a-z]+-[0-9a-f]{8,}\b", "", normalized)
    normalized = re.sub(r"evidence[_-]?[a-z0-9_-]+", "", normalized)
    normalized = re.sub(r"[\s#*_>\-|:：,，.;；。!！?？()\[\]【】\"'“”‘’]+", "", normalized)
    return normalized


def _fallback_side_conclusion(
    role: str, bundle: EvidenceBundle, decision: DebateDecision, challenges: Sequence[str]
) -> Tuple[str, Verdict, str]:
    evidence = bundle.evidence
    if _all_primary_locations_invalid(evidence):
        return "误报", Verdict.FALSE_POSITIVE, "报告位置无法映射到当前源码版本，不能证明漏洞真实存在。"
    if role == "AFFIRMATIVE":
        if _has_meaningful_flow(evidence) and not _has_protection(evidence):
            return "真实漏洞", Verdict.TRUE_POSITIVE, "报告、源码位置和数据流/调用链证据形成闭环，当前未识别到有效防护。"
        if _has_meaningful_flow(evidence) and _has_protection(evidence):
            return "真实漏洞", Verdict.TRUE_POSITIVE, "攻击路径存在较强证据，但防护是否足以消减风险仍需重点验证。"
        if _has_protection(evidence) and not _has_meaningful_flow(evidence):
            return "证据不足", Verdict.INCONCLUSIVE, "源码存在但端到端路径不足，且附近防护可能消减风险。"
        return "证据不足", Verdict.INCONCLUSIVE, "当前只能确认部分源码或局部源汇迹象，尚未证明完整攻击链。"
    if _has_meaningful_flow(evidence) and not _has_protection(evidence) and not _material_unresolved(challenges):
        return "真实漏洞", Verdict.TRUE_POSITIVE, "反方未发现能推翻路径真实性、防护缺失或直接影响的证据。"
    if _has_protection(evidence) and not _has_meaningful_flow(evidence):
        return "误报", Verdict.FALSE_POSITIVE, "缺少可验证攻击路径，且源码附近已有可能消减风险的控制。"
    if decision.verdict == Verdict.FALSE_POSITIVE:
        return "误报", Verdict.FALSE_POSITIVE, decision.reasoning_summary
    return "证据不足", Verdict.INCONCLUSIVE, "仍存在路径可达性、防护有效性或影响归因未闭环的问题。"


def _clean_final_statement(text: str, label: str) -> str:
    cleaned = text.strip()
    segments = _clean_statement_segments(cleaned, max_segments=3, label=label)
    statement = " ".join(segments).strip()
    if not statement or _looks_like_task_echo(statement):
        return ""
    return statement[:500]


def _clean_moderator_summary(text: str) -> str:
    segments = _clean_statement_segments(text, max_segments=5)
    statement = " ".join(segments).strip()
    if not statement or _looks_like_task_echo(statement):
        return ""
    return statement[:1000]


def _clean_statement_segments(text: str, max_segments: int, label: str = "") -> List[str]:
    segments: List[str] = []
    for raw_line in text.strip().splitlines():
        line = _strip_response_line(raw_line, label)
        if not line:
            continue
        for segment in _split_statement_segments(line):
            segment = _strip_response_line(segment, label)
            if not segment or _looks_like_task_echo(segment):
                continue
            segments.append(segment)
            if len(segments) >= max_segments:
                return segments
    return segments


def _strip_response_line(text: str, label: str = "") -> str:
    cleaned = text.strip("# -*\t ，,;；")
    labels = [label] if label else []
    labels.extend(item for item in ("真实漏洞", "误报", "证据不足") if item not in labels)
    label_pattern = "|".join(re.escape(item) for item in labels if item)
    if label_pattern:
        cleaned = re.sub(rf"^\s*(?:结论标签|结论|标签)\s*[:：]?\s*【?(?:{label_pattern})】?\s*[，,;；:：-]*\s*", "", cleaned)
        cleaned = re.sub(rf"^\s*【(?:{label_pattern})】\s*[，,;；:：-]*\s*", "", cleaned)
        cleaned = re.sub(rf"^\s*(?:{label_pattern})\s*[，,;；:：-]+\s*", "", cleaned)
    cleaned = re.sub(r"^\s*(?:结案陈述|结案陈词|陈述正文|正文|主持人总结|总结)\s*[:：]\s*", "", cleaned)
    return cleaned.strip()


def _split_statement_segments(text: str) -> List[str]:
    parts = re.split(r"(?<=[。！？!?])\s*", text)
    return [part.strip() for part in parts if part.strip()]


def _looks_like_task_echo(statement: str) -> bool:
    normalized = re.sub(r"\s+", "", statement.lower())
    markers = (
        "用户要求",
        "任务要求",
        "根据任务要求",
        "结论标签固定",
        "标签固定为",
        "只输出",
        "只返回",
        "1到3句话",
        "1-3句话",
        "2到5句话",
        "2-5句话",
        "markdown表格",
        "作为正方",
        "作为反方",
        "作为中立moderator",
        "作为主持人",
        "affirmative_default",
        "negative_default",
        "moderator_default",
        "给出简短结案陈述",
        "给出最终结案陈述",
        "结案陈述正文",
        "结案陈词",
        "给出唯一结论标签",
        "格式要求",
        "格式说明",
        "请用中文",
        "可审计的辩论回合",
        "我需要给出",
        "我会给出",
        "我将给出",
        "需要给出",
        "我需要输出",
        "我会输出",
        "需要输出",
        "我需要总结",
        "我会总结",
        "需要总结",
        "总结正反方核心观点",
    )
    if any(marker in normalized for marker in markers):
        return True
    first_person_task = re.search(r"(?:我|本人)?(?:需要|会|将|应该|必须).{0,12}(?:给出|输出|提供|总结|生成|撰写|写)", normalized)
    task_target = any(term in normalized for term in ("结案", "陈述", "陈词", "摘要", "总结", "标签", "任务", "要求"))
    return bool(first_person_task and task_target)


def _final_conclusion(affirmative: SideConclusion, negative: SideConclusion) -> str:
    if affirmative.label == negative.label:
        return f"【{affirmative.label}】，{affirmative.statement}；{negative.statement}"
    return f"存在分歧。正方【{affirmative.label}】，{affirmative.statement}；反方【{negative.label}】，{negative.statement}"


def _decision_from_conclusions(
    base: DebateDecision, affirmative: SideConclusion, negative: SideConclusion, final_conclusion: str
) -> DebateDecision:
    reasoning_summary = _clean_moderator_summary(final_conclusion) or base.reasoning_summary
    if affirmative.verdict == negative.verdict:
        return DebateDecision(
            verdict=affirmative.verdict,
            confidence=base.confidence,
            disputed_points=base.disputed_points,
            reasoning_summary=reasoning_summary,
            recommended_next_steps=base.recommended_next_steps,
        )
    disputed = list(base.disputed_points)
    disputed.append("正方和反方最终结论标签不一致。")
    return DebateDecision(
        verdict=Verdict.INCONCLUSIVE,
        confidence=min(base.confidence, 0.5),
        disputed_points=disputed,
        reasoning_summary=reasoning_summary,
        recommended_next_steps=base.recommended_next_steps + ["人工复核正反方分歧点后再定性。"],
    )


def _can_reach_consensus(base_decision: DebateDecision, unresolved: Sequence[str]) -> bool:
    return base_decision.verdict != Verdict.INCONCLUSIVE and not _material_unresolved(unresolved)


def _join_ids(ids: Sequence[str]) -> str:
    return ", ".join(f"`{item}`" for item in ids) if ids else "无"


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
    if _has_atlas_indexed_files(evidence):
        return False
    locations = [item for item in evidence if item.kind == EvidenceKind.SOURCE_LOCATION]
    return bool(locations) and all(not item.data.get("line_exists") for item in locations)


def _has_valid_location(evidence: Sequence[CodeEvidence]) -> bool:
    return any(item.kind == EvidenceKind.SOURCE_LOCATION and item.data.get("line_exists") for item in evidence) or _has_atlas_indexed_files(evidence)


def _has_source_root(evidence: Sequence[CodeEvidence]) -> bool:
    return any(
        item.kind == EvidenceKind.SOURCE_ROOT
        and item.data.get("source_root_exists")
        and item.data.get("source_root_is_dir")
        for item in evidence
    )


def _has_atlas_indexed_files(evidence: Sequence[CodeEvidence]) -> bool:
    return any(item.kind == EvidenceKind.SOURCE_LOCATION and _is_atlas_source(item) and item.data.get("indexed_files") for item in evidence)


def _has_atlas_trace_unavailable(evidence: Sequence[CodeEvidence]) -> bool:
    return any(_is_atlas_source(item) and item.data.get("trace_supported") is False for item in evidence)


def _is_atlas_source(item: CodeEvidence) -> bool:
    return item.source.startswith("atlas")


def _has_meaningful_flow(evidence: Sequence[CodeEvidence]) -> bool:
    for item in evidence:
        if item.kind == EvidenceKind.SARIF_CODE_FLOW and item.strength == EvidenceStrength.STRONG:
            return True
        if item.kind in {EvidenceKind.DATA_FLOW, EvidenceKind.CALL_CHAIN} and item.strength in {
            EvidenceStrength.STRONG,
            EvidenceStrength.MEDIUM,
        }:
            if item.source != "code-search":
                return True
    return False


def _has_weak_source_sink(evidence: Sequence[CodeEvidence]) -> bool:
    sources = {"code-search", "agentic-rg"}
    has_source = any(item.kind == EvidenceKind.DATA_FLOW and item.source in sources and item.data.get("source_terms") for item in evidence)
    has_sink = any(item.kind == EvidenceKind.DATA_FLOW and item.source in sources and item.data.get("sink_terms") for item in evidence)
    return has_source and has_sink


def _has_protection(evidence: Sequence[CodeEvidence]) -> bool:
    return any(item.kind == EvidenceKind.PROTECTION for item in evidence) or bool(_project_context_controls(evidence))


def _has_impact(evidence: Sequence[CodeEvidence]) -> bool:
    return any(item.kind in {EvidenceKind.IMPACT, EvidenceKind.PROJECT_CONTEXT} for item in evidence)


def _has_project_context(evidence: Sequence[CodeEvidence]) -> bool:
    return any(item.kind == EvidenceKind.PROJECT_CONTEXT for item in evidence)


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
    context_controls = _project_context_controls(evidence)
    if not protections and not context_controls:
        return "未发现针对报告路径的防护消减证据；本轮不引入防护消减假设。"
    terms = []
    for item in protections:
        terms.extend(item.data.get("terms", []))
    unique_terms = sorted(set(terms))
    parts = []
    if unique_terms:
        parts.append("报告路径附近发现候选防护控制：" + ", ".join(unique_terms))
    if context_controls:
        parts.append("Skill/项目上下文存在统一防护信息：" + "; ".join(context_controls[:3]))
    if not parts:
        return "发现防护证据，但未提取到具体控制词项；只能作为待分析防护证据。"
    return "；".join(parts)


def _project_context_controls(evidence: Sequence[CodeEvidence]) -> List[str]:
    markers = (
        "鉴权",
        "认证",
        "权限",
        "校验",
        "消毒",
        "过滤",
        "限流",
        "策略",
        "中间件",
        "网关",
        "auth",
        "permission",
        "sanitize",
        "validate",
        "policy",
        "middleware",
        "gateway",
    )
    controls = []
    for item in evidence:
        if item.kind != EvidenceKind.PROJECT_CONTEXT:
            continue
        text = (item.summary + " " + str(item.data)).lower()
        if any(marker.lower() in text for marker in markers):
            controls.append(item.summary)
    return controls


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


def _resolved_source_locations(evidence: Sequence[CodeEvidence], fallback: Sequence[SourceLocation]) -> List[SourceLocation]:
    locations: List[SourceLocation] = []
    seen = set()
    for item in evidence:
        if item.kind != EvidenceKind.SOURCE_LOCATION:
            continue
        if not item.data.get("line_exists") and not item.data.get("indexed_files"):
            continue
        for location in item.locations:
            marker = (location.file, location.line, location.column)
            if marker in seen:
                continue
            seen.add(marker)
            locations.append(location)
    return locations or list(fallback)


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
        EvidenceKind.REPORT: "输入报告",
        EvidenceKind.SOURCE_ROOT: "源码根目录",
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

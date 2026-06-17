from __future__ import annotations

import difflib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
import shutil
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .agents import DEFAULT_AFFIRMATIVE_AGENT, DEFAULT_MODERATOR_AGENT, DEFAULT_NEGATIVE_AGENT
from .evidence import EvidenceBundle
from .evidence_graph import build_evidence_graph, graph_to_markdown
from .logging_config import logger
from .llm import LLMClient
from .mcp import MCPError, MCPStdioClient
from .mcp_config import MCPServerStore
from .models import (
    AgentConfig,
    CodeEvidence,
    DebateRole,
    DebateTurn,
    EvidenceLedgerItem,
    EvidenceKind,
    EvidenceStrength,
    SourceLocation,
    Verdict,
    VerdictReport,
    VerificationCase,
    VerificationScorecard,
    to_jsonable,
)
from .source import evidence_id


LOG = logger("debate")
AGENT_ATLAS_MAX_LLM_REQUESTS = 5
DEFAULT_AGENT_ATLAS_TOOL_ROUNDS = AGENT_ATLAS_MAX_LLM_REQUESTS - 1
AGENT_ATLAS_TOOL_BATCH_LIMIT = 5
AGENT_ATLAS_MAX_MCP_CALLS = 20
MARKDOWN_REPORT_PROMPT_CHARS = 20000


@dataclass
class DebateDecision:
    verdict: Verdict
    confidence: float
    disputed_points: List[str]
    reasoning_summary: str
    recommended_next_steps: List[str]


@dataclass
class ModeratorRoundDecision:
    continue_debate: bool
    unresolved: List[str]
    summary: str


FINAL_LABELS = ("真实漏洞", "误报", "证据不足", "可达性存疑")


AGENT_ATLAS_ALLOWED_TOOLS = {
    "project",
    "search",
    "symbol",
    "calls",
    "trace",
    "path",
    "impact",
    "file_dependencies",
    "explore",
}


ENTRY_REACHABILITY_MARKERS = (
    "request",
    "response",
    "param",
    "params",
    "query",
    "body",
    "header",
    "cookie",
    "argv",
    "stdin",
    "recv",
    "route",
    "router",
    "endpoint",
    "controller",
    "servlet",
    "handler",
    "rest",
    "api",
    "http",
    "flask",
    "fastapi",
    "django",
    "express",
    "spring",
    "getparameter",
    "getheader",
    "requestmapping",
    "getmapping",
    "postmapping",
    "putmapping",
    "deletemapping",
    "@route",
    "@app.route",
    "app.get",
    "app.post",
    "router.get",
    "router.post",
    "add_url_rule",
)


SENSITIVE_INFO_TERMS: Tuple[Tuple[str, str, bool], ...] = (
    ("private_key", "private_key", True),
    ("privatekey", "privateKey", True),
    ("private key", "private key", True),
    ("secret_key", "secret_key", True),
    ("secretkey", "secretKey", True),
    ("secret key", "secret key", True),
    ("access_key", "access_key", True),
    ("accesskey", "accessKey", True),
    ("access key", "access key", True),
    ("api_key", "api_key", True),
    ("apikey", "apiKey", True),
    ("api key", "API key", True),
    ("credential", "credential", True),
    ("credentials", "credentials", True),
    ("password", "password", True),
    ("passwd", "passwd", True),
    ("token", "token", True),
    ("secret", "secret", True),
    ("密钥", "密钥", True),
    ("秘钥", "秘钥", True),
    ("密码", "密码", True),
    ("口令", "口令", True),
    ("令牌", "令牌", True),
    ("凭证", "凭证", True),
    ("sensitive information", "sensitive information", False),
    ("sensitive data", "sensitive data", False),
    ("sensitive", "sensitive", False),
    ("敏感信息", "敏感信息", False),
    ("key", "key", False),
)

SOURCE_CONTEXT_KINDS = {
    EvidenceKind.SOURCE_LOCATION,
    EvidenceKind.SARIF_CODE_FLOW,
    EvidenceKind.DATA_FLOW,
    EvidenceKind.CALL_CHAIN,
}

BUSINESS_LOGIC_PATTERNS: Tuple[Tuple[Tuple[str, ...], str], ...] = (
    (
        ("request", "req.", "args", "param", "query", "body", "stdin", "argv", "用户输入", "请求", "参数"),
        "读取外部输入或请求参数",
    ),
    (("return", "response", "send", "write", "print", "json", "返回", "响应", "输出", "写出"), "返回或写出处理结果"),
    (
        ("encrypt", "decrypt", "cipher", "crypto", "hmac", "sign", "verify", "hash", "加密", "解密", "签名", "验签"),
        "执行加解密、签名、验签或摘要计算",
    ),
    (("password", "token", "credential", "auth", "session", "login", "密码", "令牌", "凭证", "认证", "鉴权"), "处理认证、会话或凭证语义"),
    (("open(", "read(", "write(", "file", "path", "目录", "路径", "文件"), "读写文件或处理路径"),
    (("select", "insert", "update", "delete", "sql", "query", "database", "db.", "数据库"), "访问数据库或构造查询"),
    (("exec", "system", "popen", "shell", "command", "命令"), "执行命令或调用系统进程"),
    (("http", "url", "socket", "client", "网络", "请求转发"), "访问网络资源或转发请求"),
    (("log", "logger", "日志"), "记录日志或审计信息"),
)

CRYPTO_CONTEXT_MARKERS = (
    "encrypt",
    "decrypt",
    "cipher",
    "crypto",
    "hmac",
    "sign",
    "verify",
    "hash",
    "digest",
    "加密",
    "解密",
    "签名",
    "验签",
    "摘要",
)


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
        source_path: Optional[Path] = None,
        mcp_servers_file: Optional[Path] = None,
        enable_atlas_tools: bool = True,
    ):
        self.max_rounds = max_rounds
        self.affirmative_client = affirmative_client or llm_client
        self.negative_client = negative_client or llm_client
        self.moderator_client = moderator_client or llm_client
        self.affirmative_agent = _agent_or_default(affirmative_agent, DEFAULT_AFFIRMATIVE_AGENT)
        self.negative_agent = _agent_or_default(negative_agent, DEFAULT_NEGATIVE_AGENT)
        self.moderator_agent = _agent_or_default(moderator_agent, DEFAULT_MODERATOR_AGENT)
        self.progress_callback = progress_callback
        self.source_path = source_path
        self.mcp_servers_file = mcp_servers_file
        self.enable_atlas_tools = enable_atlas_tools

    def adjudicate(self, bundle: EvidenceBundle) -> VerdictReport:
        evidence = bundle.evidence
        decision = self._decide(bundle)
        turns, final_conclusion, decision = self._debate_turns(bundle, decision)
        turns = _dedupe_debate_turns(turns)
        verification_case = _build_verification_case(bundle)
        scorecard = _build_verification_scorecard(evidence, decision)
        decision = _decision_with_scorecard_summary(decision, scorecard)
        scorecard = _build_verification_scorecard(evidence, decision)
        evidence_ledger = _build_evidence_ledger(evidence, scorecard)
        evidence_graph = build_evidence_graph(evidence, decision.disputed_points)
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
            evidence_graph=evidence_graph,
            verification_case=to_jsonable(verification_case),
            evidence_ledger=to_jsonable(evidence_ledger),
            scorecard=to_jsonable(scorecard),
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
        configured_rounds = max(1, int(self.max_rounds or 1))
        max_regular_round = configured_rounds
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
                "必须增加“代码上下文业务逻辑说明”：梳理当前漏洞代码及相邻上下文的行为目的，并用它校验变量语义和影响归因；"
                "例如 key 是否为密钥，要结合后续是否参与加解密、签名、凭证校验、返回、日志或存储等上下文判断。"
                "防护消减只在源码或 Skill/项目上下文存在明确防护证据时分析；没有证据就不要引入防护消减假设。"
            ),
            bundle,
            extra=_stage_context(
                "正方第一回合",
                (
                    "优先使用 Atlas MCP 证据向上游追溯到外部输入源头。Atlas v1.5+ 支持无需预建 .atlas/atlas.db 的 Focus 查询；"
                    "若证据显示 Atlas MCP 已返回 project/open、project/status、project/files、trace 或 calls，"
                    "必须引用这些证据判断源码真实性、调用图和数据流。Atlas 缺边、未命中或 trace 不完整时，先合理怀疑工具未正确处理调用链，"
                    "转用源码阅读和 grep/ripgrep 定位调用链或数据流；找到新上游节点后再回到 Atlas 继续追溯。只有这些路径均失败时，"
                    "才可怀疑误报、不可利用漏洞或证据不足。不得把 .atlas 缺失当作 Atlas 不可用；只有 MCP 启动或工具调用失败时，才可说明 Atlas MCP 不可用。"
                ),
                challenges,
                _affirmative_evidence_hunting_context(bundle),
            ),
        ) or _affirmative_evidence_report(bundle, base_decision, challenges)
        turns: List[DebateTurn] = []
        turns.append(
            _make_debate_turn(
                role=DebateRole.AFFIRMATIVE,
                round_index=1,
                claim=affirmative_report,
                evidence_ids=source_root_ids + report_ids + location_ids + flow_ids + impact_ids,
                decision=base_decision,
                unresolved=challenges,
            )
        )
        self._emit_progress(bundle, base_decision, turns)
        negative_llm_report = self._llm_claim(
            "NEGATIVE",
            (
                "提交反方质疑报告。目标固定为：客观验证正方给出的报告源码真实性、外部/内部入口可达性、"
                "调用链、源到汇数据流、攻击影响和防护分析是否由证据支持。重点找出证据跳跃、无关 rg/Atlas 命中、"
                "把候选汇点当作可达汇点、遗漏调用前提或浑水摸鱼的地方。"
                "你必须像正方一样自主达成反方目标：不以正方报告为准，而是围绕原始报告、源码位置、Atlas/rg/源码证据独立重构调用链和数据流，"
                "主动寻找能推翻、削弱或限定正方主张的新断点；如果证据不足，应说明还需补哪类证据，而不是只复述正方结论。"
                "只能引用提示中给出的证据 ID。"
                "如果报告涉及敏感信息，必须首先根据证据链确认相关参数或变量是否真实承载敏感信息；"
                "例如 key 可能是密钥，也可能只是普通标识、索引或业务字段，不能仅凭变量名扩大为敏感信息泄露。"
                "必须核验正方的代码上下文业务逻辑说明是否与源码一致，并用上下文行为判断变量语义；"
                "如果后续没有加解密、签名、凭证校验等操作，应指出 key 被认定为密钥的证据不足。"
                "防护消减只能基于源码或 Skill/项目上下文中的明确防护证据质疑；没有证据时不得凭空假设统一防护。"
            ),
            bundle,
            extra=_stage_context(
                "反方第一回合",
                "正方证据报告：\n" + affirmative_report,
                challenges,
                _negative_autonomous_audit_context(bundle),
            ),
        )
        negative_report = negative_llm_report or _negative_challenge_report(bundle, challenges, affirmative_report)
        turns.append(
            _make_debate_turn(
                role=DebateRole.NEGATIVE,
                round_index=1,
                claim=negative_report,
                evidence_ids=source_root_ids + report_ids + location_ids + flow_ids + protection_ids + impact_ids + tool_diag_ids,
                resolved=not challenges,
                decision=base_decision,
                unresolved=challenges,
            )
        )
        self._emit_progress(bundle, base_decision, turns)
        unresolved = _merge_challenges(challenges, _negative_disputed_points(negative_report) if negative_llm_report else [])
        last_negative = negative_report
        moderator_decision = self._moderator_round_review(
            bundle,
            base_decision,
            turns,
            challenges,
            unresolved,
            round_index=1,
            max_regular_round=max_regular_round,
        )
        turns.append(
            _make_debate_turn(
                role=DebateRole.MODERATOR,
                round_index=1,
                claim=moderator_decision.summary,
                evidence_ids=[item.evidence_id for item in evidence],
                resolved=not moderator_decision.continue_debate,
                decision=base_decision,
                unresolved=moderator_decision.unresolved,
            )
        )
        self._emit_progress(bundle, base_decision, turns)
        unresolved = moderator_decision.unresolved
        if not moderator_decision.continue_debate:
            return self._finalize_debate(bundle, base_decision, challenges, turns, 1)

        for round_index in range(2, max_regular_round + 1):
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
                _make_debate_turn(
                    role=DebateRole.AFFIRMATIVE,
                    round_index=round_index,
                    claim=clarification,
                    evidence_ids=answer_ids,
                    resolved=not _material_unresolved(unresolved),
                    decision=base_decision,
                    unresolved=unresolved,
                )
            )
            self._emit_progress(bundle, base_decision, turns)
            negative_llm_review = self._llm_claim(
                "NEGATIVE",
                (
                    "复审正方澄清。指出已经闭环的问题和仍然不成立的断点，并给出是否继续质疑。"
                    "重点仍是攻击链真实性、代码上下文业务逻辑、攻击前提、防护消减、敏感信息真实性和影响归因。"
                    "必须自主复核正方新增论证：独立核对证据 ID、报告位置、Atlas/rg/源码上下文和调用链节点，"
                    "判断正方是否真的补齐缺口；发现证据跳跃、复读或未证明事实时继续质疑，并提出下一步应补证的具体方向。"
                ),
                bundle,
                extra=_stage_context(
                    f"反方第 {round_index} 回合复审",
                    "正方澄清：\n" + clarification,
                    unresolved,
                    _negative_autonomous_audit_context(bundle),
                ),
            )
            negative_review = negative_llm_review or _negative_review_report(bundle, unresolved, clarification, round_index)
            next_unresolved = _merge_challenges(
                [item for item in unresolved if _challenge_still_material(evidence, item)],
                _negative_disputed_points(negative_review) if negative_llm_review else [],
            )
            turns.append(
                _make_debate_turn(
                    role=DebateRole.NEGATIVE,
                    round_index=round_index,
                    claim=negative_review,
                    evidence_ids=source_root_ids + report_ids + location_ids + flow_ids + protection_ids + impact_ids + tool_diag_ids,
                    resolved=not _material_unresolved(next_unresolved),
                    decision=base_decision,
                    unresolved=next_unresolved,
                )
            )
            self._emit_progress(bundle, base_decision, turns)
            last_negative = negative_review
            moderator_decision = self._moderator_round_review(
                bundle,
                base_decision,
                turns,
                challenges,
                next_unresolved,
                round_index=round_index,
                max_regular_round=max_regular_round,
            )
            turns.append(
                _make_debate_turn(
                    role=DebateRole.MODERATOR,
                    round_index=round_index,
                    claim=moderator_decision.summary,
                    evidence_ids=[item.evidence_id for item in evidence],
                    resolved=not moderator_decision.continue_debate,
                    decision=base_decision,
                    unresolved=moderator_decision.unresolved,
                )
            )
            self._emit_progress(bundle, base_decision, turns)
            unresolved = moderator_decision.unresolved
            if not moderator_decision.continue_debate:
                return self._finalize_debate(bundle, base_decision, challenges, turns, round_index)

        return self._finalize_debate(bundle, base_decision, challenges, turns, configured_rounds)

    def _finalize_debate(
        self,
        bundle: EvidenceBundle,
        base_decision: DebateDecision,
        challenges: Sequence[str],
        turns: List[DebateTurn],
        final_round: int,
    ) -> Tuple[List[DebateTurn], str, DebateDecision]:
        evidence = bundle.evidence
        moderator_summary = self._moderator_summary(
            bundle,
            base_decision,
            challenges,
            turns,
        )
        evidence_graph = build_evidence_graph(evidence, challenges)
        fallback_conclusion = _fallback_moderator_final_conclusion(bundle, base_decision, challenges)
        final_conclusion = _append_evidence_graph_markdown(
            _ensure_moderator_final_label(moderator_summary, base_decision) if moderator_summary else fallback_conclusion,
            evidence_graph,
        )
        decision = _decision_from_moderator_conclusion(base_decision, final_conclusion)
        turns.append(
            _make_debate_turn(
                role=DebateRole.MODERATOR,
                round_index=final_round,
                claim=final_conclusion,
                evidence_ids=[item.evidence_id for item in evidence],
                resolved=decision.verdict != Verdict.INCONCLUSIVE,
                decision=decision,
                unresolved=decision.disputed_points,
            )
        )
        self._emit_progress(bundle, decision, turns, final_conclusion=final_conclusion)
        return turns, final_conclusion, decision

    def _moderator_round_review(
        self,
        bundle: EvidenceBundle,
        base_decision: DebateDecision,
        turns: Sequence[DebateTurn],
        challenges: Sequence[str],
        candidate_unresolved: Sequence[str],
        *,
        round_index: int,
        max_regular_round: int,
    ) -> ModeratorRoundDecision:
        repetition_issue = _moderator_repetition_issue(turns)
        reached_round_limit = round_index >= max_regular_round
        fallback = _fallback_moderator_round_decision(
            base_decision,
            candidate_unresolved,
            round_index=round_index,
            reached_round_limit=reached_round_limit,
            repetition_issue=repetition_issue,
        )
        round_context = "\n\n".join(
            f"{_role_label(turn.role.value)}第 {turn.round_index} 回合：\n{_turn_prompt_text(turn)}"
            for turn in turns
            if turn.round_index == round_index and turn.role != DebateRole.MODERATOR
        )
        issue_context = f"检测到复读：{repetition_issue}" if repetition_issue else ""
        llm_review = self._llm_response(
            "MODERATOR",
            (
                "分析本轮正反方陈述，裁定是否需要继续下一轮。"
                "必须客观说明双方一致点、仍未闭环争议、是否存在复读或证据跳跃。"
                "必须像正方一样自主达成 Moderator 目标：独立审查输入报告读取是否正常、证据链是否覆盖源码位置、代码上下文业务逻辑、入口可达性、调用链、数据流、影响、防护和敏感信息语义，"
                "判断正反方是否围绕报告验证而非复读或引用无关命中；必要时主动提出下一轮必须解决的证据缺口。"
                "只能依据证据链和本轮陈述，不得替任一方新增事实。"
            ),
            bundle,
            extra=_stage_context(
                f"Moderator 第 {round_index} 回合分析",
                (
                    f"本轮正反方陈述：\n{round_context}\n\n"
                    f"候选未闭环争议：\n{_challenge_lines(candidate_unresolved)}\n"
                    f"{issue_context}"
                ),
                challenges,
                _moderator_autonomous_review_context(bundle, turns, candidate_unresolved),
            ),
            output_instruction=(
                "按以下字段输出：是否继续下一轮：是/否；未闭环争议：逐条列出或写无；"
                "分析：2 到 4 句话。不要复述任务、角色或格式要求。"
            ),
        )
        parsed = _parse_moderator_round_decision(llm_review, fallback, candidate_unresolved)
        decision = parsed or fallback
        if reached_round_limit and decision.continue_debate:
            decision = ModeratorRoundDecision(
                continue_debate=False,
                unresolved=decision.unresolved,
                summary=_append_moderator_limit_notice(decision.summary, round_index),
            )
        return decision

    def _emit_progress(
        self,
        bundle: EvidenceBundle,
        decision: DebateDecision,
        turns: Sequence[DebateTurn],
        final_conclusion: str = "",
    ) -> None:
        if self.progress_callback is None:
            return
        verification_case = _build_verification_case(bundle)
        scorecard = _build_verification_scorecard(bundle.evidence, decision)
        self.progress_callback(
            VerdictReport(
                finding_id=bundle.finding.finding_id,
                rule_id=bundle.finding.rule_id,
                verdict=decision.verdict,
                confidence=round(decision.confidence, 2),
                reasoning_summary=decision.reasoning_summary,
                final_conclusion=final_conclusion,
                evidence_chain=bundle.evidence,
                debate=_dedupe_debate_turns(turns),
                disputed_points=decision.disputed_points,
                protection_assessment=_protection_assessment(bundle.evidence),
                impact_assessment=_impact_assessment(bundle.evidence),
                source_locations=_resolved_source_locations(bundle.evidence, bundle.finding.locations),
                recommended_next_steps=decision.recommended_next_steps,
                evidence_graph=build_evidence_graph(bundle.evidence, decision.disputed_points),
                verification_case=to_jsonable(verification_case),
                evidence_ledger=to_jsonable(_build_evidence_ledger(bundle.evidence, scorecard)),
                scorecard=to_jsonable(scorecard),
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
        if _has_reachability_doubt(evidence):
            challenges.append("局部漏洞路径存在，但尚未证明外部或内部 REST/API/接口入口能够调用到漏洞相关函数。")
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
            f"研判用例：\n{_verification_case_prompt(_build_verification_case(bundle))}\n"
            f"当前证据评分卡：\n{_scorecard_prompt(_build_verification_scorecard(bundle.evidence, None))}\n"
            f"证据：\n" + _evidence_prompt(bundle.evidence) + "\n"
            "证据解释约束：SOURCE_ROOT 只能证明任务已配置源码根目录，不能替代具体 SOURCE_LOCATION、CALL_CHAIN 或 DATA_FLOW；"
            "rg/grep 证据必须围绕报告位置、报告符号、codeFlow 或调用邻域解释，只能作为候选补证，不能单独证明源汇可达；"
            "若存在 agent-atlas-mcp 或 atlas-agent-mcp 证据，应优先按 MCP 的 project/status、project/files、trace、calls 结果研判；"
            "若 Atlas 数据库存在但 trace 结果为 empty/partial/No data node，应转而从 calls 调用图和源码片段交叉验证重构数据流；"
            "若 Atlas 数据库存在但 trace_supported=false，只能说明当前工具无法导出 trace，不得说 .atlas 缺失或未构建。\n"
            f"补充上下文或质疑：\n{extra}\n"
            f"{output_instruction}"
        )
        return self._complete_with_agent_atlas_tools(client, role, system, user, bundle)

    def _complete_with_agent_atlas_tools(
        self, client: LLMClient, role: str, system: str, user: str, bundle: EvidenceBundle
    ) -> Optional[str]:
        if not self._atlas_tools_available():
            return client.complete(system, user)
        tool_user = user + "\n\n" + _agent_atlas_tool_instruction(self.source_path)
        mcp_client: Optional[MCPStdioClient] = None
        remaining_mcp_calls = AGENT_ATLAS_MAX_MCP_CALLS
        try:
            for round_index in range(_agent_atlas_tool_round_limit()):
                response = client.complete(system, tool_user)
                if not response:
                    return None
                calls = _parse_agent_atlas_tool_calls(response)
                if not calls:
                    return _parse_agent_final_text(response) or response
                LOG.info(
                    "%s Agent 请求 Atlas MCP 工具 round=%s tools=%s",
                    _role_label(role),
                    round_index + 1,
                    [
                        str(call.get("tool") or call.get("name") or "").strip()
                        for call in calls[: min(AGENT_ATLAS_TOOL_BATCH_LIMIT, remaining_mcp_calls)]
                    ],
                )
                if mcp_client is None:
                    mcp_client = self._start_atlas_mcp_client()
                observations, used_mcp_calls = self._execute_agent_atlas_tool_calls(
                    mcp_client, role, bundle, calls, remaining_mcp_calls
                )
                remaining_mcp_calls = max(0, remaining_mcp_calls - used_mcp_calls)
                tool_user += (
                    "\n\nAtlas MCP 工具观察（这些观察已作为新证据加入 evidence_chain，后续论断必须引用对应 evidence_id）：\n"
                    + "\n".join(observations)
                    + (
                        "\n\n本回合 Atlas MCP 工具调用预算已经用完。请基于当前证据输出本回合正文，不要再输出工具 JSON。"
                        if remaining_mcp_calls <= 0
                        else "\n\n请基于当前证据继续。若仍需 Atlas，请再次只输出 atlas_tool_calls JSON；"
                        "若证据已足够，请输出本回合正文，不要再输出工具 JSON。"
                    )
                )
                if remaining_mcp_calls <= 0:
                    break
            response = client.complete(
                system,
                tool_user
                + "\n\nAtlas MCP 工具调用轮次或工具调用预算已经用完。现在必须只输出本回合中文 Markdown 正文，"
                "禁止再输出 atlas_tool_calls、tool_calls 或任何 JSON。若证据仍不足，请在正文中说明已尝试的工具路径和剩余缺口。",
            )
            if not response:
                return None
            if _parse_agent_atlas_tool_calls(response):
                bundle.evidence.append(
                    CodeEvidence(
                        evidence_id=evidence_id(bundle.finding.finding_id, "agent-atlas", role.lower(), "rounds-exhausted"),
                        kind=EvidenceKind.TOOL_DIAGNOSTIC,
                        strength=EvidenceStrength.WEAK,
                        summary=f"{_role_label(role)} Agent Atlas MCP 工具轮次耗尽后仍请求工具；已忽略该 JSON 并回退到静态正文",
                        source=f"agent-atlas-mcp:{role.lower()}",
                        data={"agent_atlas_tool": True, "mcp_success": False, "rounds_exhausted": True},
                    )
                )
                return _parse_agent_final_text(response) or None
            return _parse_agent_final_text(response) or response
        except (MCPError, OSError, ValueError) as exc:
            bundle.evidence.append(
                CodeEvidence(
                    evidence_id=evidence_id(bundle.finding.finding_id, "agent-atlas", role.lower(), "failed"),
                    kind=EvidenceKind.TOOL_DIAGNOSTIC,
                    strength=EvidenceStrength.WEAK,
                    summary=f"{_role_label(role)} Agent 自主 Atlas MCP 会话失败：{exc}",
                    source=f"agent-atlas-mcp:{role.lower()}",
                    data={"agent_atlas_tool": True, "mcp_success": False, "error": str(exc)},
                )
            )
            return client.complete(system, user)
        finally:
            if mcp_client is not None:
                mcp_client.close()

    def _atlas_tools_available(self) -> bool:
        return bool(self.enable_atlas_tools and self.source_path)

    def _start_atlas_mcp_client(self) -> MCPStdioClient:
        if self.source_path is None:
            raise ValueError("未配置源码路径，无法启动 Atlas MCP")
        source_path = self.source_path.expanduser().resolve()
        command: List[str]
        cwd = source_path
        env: Dict[str, str] = {}
        if self.mcp_servers_file is not None:
            server = MCPServerStore(self.mcp_servers_file).default_for_kind("atlas")
            if server is not None:
                command, cwd, env = server.command_for_project(source_path)
            else:
                binary = shutil.which("atlas")
                if not binary:
                    raise ValueError("未配置 Atlas MCP Server，且 PATH 中未找到 atlas")
                command = [binary, "mcp", "--log-format", "json"]
        else:
            binary = shutil.which("atlas")
            if not binary:
                raise ValueError("未配置 Atlas MCP Server，且 PATH 中未找到 atlas")
            command = [binary, "mcp", "--log-format", "json"]
        client = MCPStdioClient(command, cwd=cwd, env=env)
        client.start()
        return client

    def _execute_agent_atlas_tool_calls(
        self,
        client: MCPStdioClient,
        role: str,
        bundle: EvidenceBundle,
        calls: Sequence[Dict[str, Any]],
        remaining_mcp_calls: int,
    ) -> Tuple[List[str], int]:
        observations: List[str] = []
        used_mcp_calls = 0
        batch_limit = min(AGENT_ATLAS_TOOL_BATCH_LIMIT, max(0, remaining_mcp_calls))
        if batch_limit <= 0:
            return ["- 本回合 Atlas MCP 工具调用预算已用完，本批工具调用未执行"], 0
        if len(calls) > batch_limit:
            observations.append(f"- 本批请求了 {len(calls)} 个工具调用，仅执行前 {batch_limit} 个以遵守本回合预算")
        for index, call in enumerate(calls[:batch_limit], start=1):
            tool = str(call.get("tool") or call.get("name") or "").strip()
            arguments = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
            arguments = _normalize_agent_atlas_tool_arguments(tool, arguments, self.source_path, bundle)
            if tool not in AGENT_ATLAS_ALLOWED_TOOLS:
                evidence = CodeEvidence(
                    evidence_id=evidence_id(bundle.finding.finding_id, "agent-atlas", role.lower(), str(len(bundle.evidence)), "blocked", tool),
                    kind=EvidenceKind.TOOL_DIAGNOSTIC,
                    strength=EvidenceStrength.WEAK,
                    summary=f"{_role_label(role)} Agent 请求了不允许的 Atlas MCP 工具 `{tool}`；已拒绝执行",
                    source=f"agent-atlas-mcp:{role.lower()}",
                    data={"agent_atlas_tool": True, "mcp_tool": tool, "mcp_success": False, "blocked": True},
                )
                bundle.evidence.append(evidence)
                observations.append(f"- `{evidence.evidence_id}` blocked `{tool}`")
                continue
            LOG.info("%s Agent 调用 Atlas MCP tool=%s arguments=%s", _role_label(role), tool, _compact_agent_log_json(arguments))
            try:
                used_mcp_calls += 1
                payload, raw_text, is_error = _agent_mcp_tool_payload(client.call_tool(tool, arguments))
            except (MCPError, OSError, ValueError) as exc:
                evidence = _agent_atlas_tool_failure_evidence(
                    bundle.finding.finding_id,
                    role,
                    len(bundle.evidence) + index,
                    tool,
                    arguments,
                    exc,
                )
                bundle.evidence.append(evidence)
                observations.append(f"- `{evidence.evidence_id}` {evidence.summary}；结果摘要：{_compact_text(str(exc), 1200)}")
                LOG.warning("%s Agent Atlas MCP tool=%s failed: %s", _role_label(role), tool, exc)
                break
            evidence = _agent_atlas_tool_evidence(
                bundle.finding.finding_id,
                role,
                len(bundle.evidence) + index,
                tool,
                arguments,
                payload,
                raw_text,
                is_error,
            )
            bundle.evidence.append(evidence)
            observations.append(
                f"- `{evidence.evidence_id}` {evidence.summary}；位置："
                + (" -> ".join(location.display() for location in evidence.locations[:8]) if evidence.locations else "无")
                + "；结果摘要："
                + _compact_text(raw_text or json.dumps(payload, ensure_ascii=False), 1200)
            )
            LOG.info("%s Agent Atlas MCP tool=%s success=%s evidence=%s", _role_label(role), tool, not is_error, evidence.evidence_id)
        return observations, used_mcp_calls

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

    def _moderator_summary(
        self,
        bundle: EvidenceBundle,
        decision: DebateDecision,
        challenges: Sequence[str],
        turns: Sequence[DebateTurn],
    ) -> Optional[str]:
        turn_context = "\n\n".join(
            f"{_role_label(turn.role.value)}第 {turn.round_index} 回合：\n{_turn_prompt_text(turn)}" for turn in turns[-8:]
        )
        llm_summary = self._llm_response(
            "MODERATOR",
            (
                "作为中立 Moderator，负责最终总结和结案。总结正反方核心观点、双方一致点、主要分歧、证据闭环状态和最终研判。"
                "必须自主串联证据链并审查双方是否达成各自目标：正方是否证明可达攻击链，反方是否客观验证断点，"
                "Moderator 是否识别了复读、异常报告读取、证据跳跃和仍未闭环缺口。"
                "不得新增证据链之外的新事实；不得替任一方辩护；只基于双方陈述和证据 ID 做客观归纳。"
                "必须给出唯一结论标签：真实漏洞、误报、证据不足、可达性存疑。输出 2 到 5 句话，不要使用 Markdown 表格。"
            ),
            bundle,
            extra=_stage_context(
                "主持人总结",
                (
                    f"自动裁决摘要：{decision.reasoning_summary}\n"
                    f"自动裁决标签参考：{_moderator_label_from_decision(decision)}\n"
                    f"最近回合：\n{turn_context}"
                ),
                challenges,
                _moderator_autonomous_review_context(bundle, turns, challenges),
            ),
            output_instruction=(
                "只返回主持人最终总结正文 2 到 5 句话；开头必须包含一个结论标签，如【真实漏洞】、【误报】、"
                "【证据不足】或【可达性存疑】；不要说明你要做什么，不要复述任务、标签或格式要求。"
            ),
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
            if _has_reachability_doubt(evidence):
                return DebateDecision(
                    verdict=Verdict.INCONCLUSIVE,
                    confidence=0.56,
                    disputed_points=challenges,
                    reasoning_summary="局部源码或源汇路径存在，但未证明外部或内部 REST/API/接口入口能够调用到漏洞相关函数，存在废弃代码或不可达路径风险。",
                    recommended_next_steps=["补充从 REST/API/内部接口入口到漏洞函数的调用链；若确认无入口调用，应按废弃代码或不可达路径处理。"],
                )
            return DebateDecision(
                verdict=Verdict.TRUE_POSITIVE,
                confidence=0.82 if _has_project_context(evidence) else 0.76,
                disputed_points=challenges,
                reasoning_summary="该发现可以解析到真实代码，并存在已验证的路径/数据流证据，当前未识别到有效缓解防护。",
                recommended_next_steps=["人工验证利用前提，并根据资产影响确定修复优先级。"],
            )
        if _has_meaningful_flow(evidence) and _has_protection(evidence):
            if _has_reachability_doubt(evidence):
                return DebateDecision(
                    verdict=Verdict.INCONCLUSIVE,
                    confidence=0.54,
                    disputed_points=challenges,
                    reasoning_summary="局部漏洞路径和防护候选均存在，但入口可达性未闭环，无法证明 REST/API/内部接口会触发该函数。",
                    recommended_next_steps=["先补齐入口到漏洞函数的调用链，再评估防护是否覆盖该路径。"],
                )
            return DebateDecision(
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.58,
                disputed_points=challenges,
                reasoning_summary="可疑漏洞路径看起来真实，但附近防护逻辑是否有效仍需要人工复核。",
                recommended_next_steps=["审查被引用的防护代码，并测试攻击者可控输入是否能绕过。"],
            )
        if _has_weak_source_sink(evidence) and not _has_protection(evidence):
            if _has_reachability_doubt(evidence):
                return DebateDecision(
                    verdict=Verdict.INCONCLUSIVE,
                    confidence=0.5,
                    disputed_points=challenges,
                    reasoning_summary="代码位置存在且包含局部源点/汇点迹象，但未证明 REST/API/内部接口入口能够调用到漏洞相关函数。",
                    recommended_next_steps=["使用 Atlas calls/search 或源码阅读补齐入口调用链；确认是否为废弃代码。"],
                )
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
            "### 3. 代码上下文业务逻辑说明",
            _code_context_business_logic_report(evidence),
            "### 4. 函数调用链与数据流",
            _flow_report(evidence),
            "### 5. 攻击链",
            _attack_chain_report(bundle),
            "### 6. 攻击前提与限制",
            _attack_prerequisite_report(evidence, challenges),
            "### 7. 防护消减分析",
            _protection_assessment(evidence),
            "### 8. 攻击影响",
            _impact_assessment(evidence),
            "### 9. PoC/EXP",
            _poc_report(evidence),
            "### 10. 正方补证策略",
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
            "### 5. 代码上下文业务逻辑核验",
            _negative_business_logic_challenge(evidence),
            "### 6. 敏感信息真实性",
            _negative_sensitive_info_challenge(evidence),
            "### 7. 攻击影响是否被夸大",
            _negative_impact_challenge(evidence),
            "### 8. 待正方澄清的问题",
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


def _agent_atlas_tool_instruction(source_path: Optional[Path]) -> str:
    return (
        "Atlas MCP 自主工具调用：\n"
        f"- 源码根目录：{source_path}\n"
        "- 你可以自主决定是否调用 Atlas MCP；如需调用，当前回复必须只输出 JSON，不要夹杂解释。\n"
        "- JSON 格式：{\"atlas_tool_calls\":[{\"tool\":\"project\",\"arguments\":{\"action\":\"open\",\"project_path\":\"源码根目录\",\"storage\":\"auto\"}}]}\n"
        "- 可用工具：project, search, symbol, calls, trace, path, impact, file_dependencies, explore。\n"
        "- 禁止调用 index；project/open 只用于激活项目，不能附加 scan_files 或 background。\n"
        "- Atlas Focus 由 search 触发：open 后优先围绕报告中的文件、符号和行号调用 search，并给 search 传入尽量窄的 scope，"
        "例如 {\"query\":\"危险函数或类名\",\"scope\":\"项目相对路径\",\"limit\":20}。\n"
        "- 如果 project/status 提示 No project facts have been materialized yet，这不是 Atlas 不可用；应先执行 scoped search，"
        "再继续 calls、trace、symbol、path 等追溯。\n"
        "- 大型项目禁止一上来做全项目宽泛 search；先用报告位置的项目相对文件路径作为 scope。\n"
        "- 每个 Agent 回合最多 5 次 LLM 调度（含最终正文）和 20 次 Atlas MCP 工具调用。\n"
        "- 每次最多 5 个 tool call。工具观察返回后，你可以继续请求工具，也可以输出本回合正文。\n"
    )


def _agent_atlas_tool_round_limit() -> int:
    raw = os.environ.get("VULN_JUDGER_AGENT_ATLAS_TOOL_ROUNDS")
    if raw:
        try:
            return max(0, min(DEFAULT_AGENT_ATLAS_TOOL_ROUNDS, int(raw)))
        except ValueError:
            pass
    return DEFAULT_AGENT_ATLAS_TOOL_ROUNDS


def _normalize_agent_atlas_tool_arguments(
    tool: str,
    arguments: Dict[str, Any],
    source_path: Optional[Path],
    bundle: Optional[EvidenceBundle] = None,
) -> Dict[str, Any]:
    normalized = dict(arguments)
    if tool == "project" and str(normalized.get("action") or "").strip().lower() == "open":
        normalized.pop("scan_files", None)
        normalized.pop("background", None)
        if source_path is not None and not normalized.get("project_path"):
            normalized["project_path"] = str(source_path)
        normalized.setdefault("storage", "auto")
    if tool == "search":
        normalized.setdefault("limit", 20)
        if _optional_int(normalized.get("limit")) and int(normalized["limit"]) > 50:
            normalized["limit"] = 50
        if bundle is not None and source_path is not None and not normalized.get("scope"):
            scope = _agent_atlas_default_search_scope(bundle, source_path)
            if scope:
                normalized["scope"] = scope
        if bundle is not None and source_path is not None and normalized.get("scope"):
            file_scope = _agent_atlas_file_scope_for_directory(bundle, source_path, str(normalized.get("scope") or ""))
            if file_scope:
                normalized["scope"] = file_scope
    if tool in {"calls", "impact", "explore"}:
        _promote_agent_symbol_alias(normalized)
        _promote_agent_include_code_alias(normalized)
        if tool == "calls" and isinstance(normalized.get("direction"), str):
            normalized["direction"] = _normalize_agent_calls_direction(str(normalized["direction"]))
        normalized.pop("function", None)
        normalized.pop("name", None)
        normalized.pop("query", None)
        normalized.pop("scope", None)
        if tool in {"calls", "impact"}:
            normalized.pop("includeCode", None)
    if tool == "symbol":
        _promote_agent_symbol_alias(normalized)
        _promote_agent_include_code_alias(normalized)
        if normalized.get("scope") and not normalized.get("file_path"):
            normalized["file_path"] = normalized.get("scope")
        normalized.pop("name", None)
        normalized.pop("kind", None)
        normalized.pop("query", None)
        normalized.pop("scope", None)
    if tool == "trace":
        if normalized.get("start") and not normalized.get("from"):
            normalized["from"] = normalized.get("start")
        if normalized.get("end") and not normalized.get("to"):
            normalized["to"] = normalized.get("end")
        if not normalized.get("kind"):
            if normalized.get("from") and normalized.get("to"):
                normalized["kind"] = "forward"
            elif normalized.get("file_path") or normalized.get("file"):
                normalized["kind"] = "point"
        if normalized.get("file") and not normalized.get("file_path"):
            normalized["file_path"] = normalized.get("file")
        normalized.pop("start", None)
        normalized.pop("end", None)
        normalized.pop("file", None)
        normalized.pop("variables", None)
    return normalized


def _promote_agent_symbol_alias(arguments: Dict[str, Any]) -> None:
    if arguments.get("symbol"):
        return
    for key in ("qualified_name", "function", "name", "query"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            arguments["symbol"] = value.strip()
            return


def _promote_agent_include_code_alias(arguments: Dict[str, Any]) -> None:
    if "include_details" in arguments:
        if "includeCode" not in arguments:
            arguments["includeCode"] = bool(arguments.get("include_details"))
        arguments.pop("include_details", None)


def _normalize_agent_calls_direction(value: str) -> str:
    normalized = value.strip().lower()
    aliases = {
        "upstream": "incoming",
        "up": "incoming",
        "callers": "incoming",
        "caller": "incoming",
        "incoming": "incoming",
        "downstream": "outgoing",
        "down": "outgoing",
        "callees": "outgoing",
        "callee": "outgoing",
        "outgoing": "outgoing",
        "both": "both",
    }
    return aliases.get(normalized, value)


def _agent_atlas_default_search_scope(bundle: EvidenceBundle, source_path: Path) -> str:
    source_root = source_path.expanduser().resolve()
    source_name = source_root.name
    for location in getattr(bundle.finding, "locations", []) or []:
        raw_file = str(getattr(location, "file", "") or "").strip()
        if not raw_file:
            continue
        candidates = _agent_atlas_scope_candidates(raw_file, source_root, source_name)
        for candidate in candidates:
            if (source_root / candidate).exists():
                return candidate
        if candidates:
            return candidates[0]
    return ""


def _agent_atlas_file_scope_for_directory(bundle: EvidenceBundle, source_path: Path, scope: str) -> str:
    cleaned_scope = scope.replace("\\", "/").strip().strip("/")
    if not cleaned_scope:
        return ""
    source_root = source_path.expanduser().resolve()
    scope_path = source_root / cleaned_scope
    if not scope_path.is_dir():
        return ""
    source_name = source_root.name
    for location in getattr(bundle.finding, "locations", []) or []:
        raw_file = str(getattr(location, "file", "") or "").strip()
        for candidate in _agent_atlas_scope_candidates(raw_file, source_root, source_name):
            if candidate == cleaned_scope or candidate.startswith(cleaned_scope + "/"):
                candidate_path = source_root / candidate
                if candidate_path.is_file():
                    return candidate
    return ""


def _agent_atlas_scope_candidates(raw_file: str, source_root: Path, source_name: str) -> List[str]:
    cleaned = raw_file.replace("\\", "/").strip()
    candidates: List[str] = []
    path = Path(cleaned)
    if path.is_absolute():
        try:
            candidates.append(path.resolve().relative_to(source_root).as_posix())
        except ValueError:
            candidates.append(path.name)
    else:
        candidates.append(cleaned)
        parts = cleaned.split("/")
        if len(parts) > 1 and parts[0] == parts[1]:
            candidates.append("/".join(parts[1:]))
        prefix = source_name + "/"
        while cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
            candidates.append(cleaned)
    result: List[str] = []
    for candidate in candidates:
        candidate = candidate.lstrip("/")
        if candidate and candidate not in result:
            result.append(candidate)
    return result


def _parse_agent_atlas_tool_calls(response: str) -> List[Dict[str, Any]]:
    payload = _json_object_from_text(response)
    if not isinstance(payload, dict):
        return []
    calls = payload.get("atlas_tool_calls") or payload.get("tool_calls") or []
    if not isinstance(calls, list):
        return []
    return [item for item in calls if isinstance(item, dict)]


def _parse_agent_final_text(response: str) -> str:
    payload = _json_object_from_text(response)
    if isinstance(payload, dict):
        for key in ("final", "final_answer", "content", "message"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _json_object_from_text(text: str) -> Optional[Dict[str, Any]]:
    stripped = (text or "").strip()
    if not stripped:
        return None
    candidates = [stripped]
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, flags=re.DOTALL)
    if fence:
        candidates.insert(0, fence.group(1).strip())
    first = stripped.find("{")
    last = stripped.rfind("}")
    if first >= 0 and last > first:
        candidates.append(stripped[first : last + 1])
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _agent_mcp_tool_payload(response: Dict[str, Any]) -> Tuple[Any, str, bool]:
    if response.get("error"):
        return response.get("error"), str(response.get("error")), True
    result = response.get("result") or {}
    is_error = bool(result.get("isError"))
    content = result.get("content") or []
    texts = [str(item.get("text") or "") for item in content if item.get("type") == "text"]
    text = "\n".join(item for item in texts if item)
    payload = _parse_agent_mcp_text_payload(text) if text else {}
    return payload, text, is_error


def _parse_agent_mcp_text_payload(text: str) -> Any:
    try:
        parsed: Any = json.loads(text)
    except json.JSONDecodeError:
        return _agent_mcp_partial_json(text) or text
    for _ in range(2):
        if not isinstance(parsed, str):
            return parsed
        stripped = parsed.strip()
        if not stripped or stripped[0] not in "{[":
            return parsed
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return _agent_mcp_partial_json(stripped) or parsed
    return parsed


def _agent_mcp_partial_json(text: str) -> Optional[Dict[str, Any]]:
    if not text.lstrip().startswith("{"):
        return None
    result: Dict[str, Any] = {"truncated_json": True}
    for key in ("ok", "partial_result"):
        match = re.search(rf'"{key}"\s*:\s*(true|false)', text)
        if match:
            result[key] = match.group(1) == "true"
    for key in ("kind", "query_id"):
        match = re.search(rf'"{key}"\s*:\s*"([^"]+)"', text)
        if match:
            result[key] = match.group(1)
    language = _first_regex_group(r'"language"\s*:\s*"([^"]+)"', text)
    capability_level = _first_regex_group(r'"capability_level"\s*:\s*"([^"]+)"', text)
    if language or capability_level:
        result["capability"] = {"language": language, "capability_level": capability_level}
    return result if len(result) > 1 else None


def _first_regex_group(pattern: str, text: str) -> Optional[str]:
    match = re.search(pattern, text)
    return match.group(1) if match else None


def _agent_atlas_tool_evidence(
    finding_id: str,
    role: str,
    sequence: int,
    tool: str,
    arguments: Dict[str, Any],
    payload: Any,
    raw_text: str,
    is_error: bool,
) -> CodeEvidence:
    locations = _dedupe_agent_atlas_locations(
        _agent_atlas_argument_locations(tool, arguments) + _agent_atlas_locations(payload)
    )
    success = not is_error
    kind = EvidenceKind.TOOL_DIAGNOSTIC
    if success and tool in {"search", "symbol"}:
        kind = EvidenceKind.SOURCE_LOCATION
    elif success and tool == "project" and str(arguments.get("action") or "") == "files":
        kind = EvidenceKind.SOURCE_LOCATION
    elif success and tool in {"calls", "path"}:
        kind = EvidenceKind.CALL_CHAIN
    elif success and tool == "trace":
        trace_kind = str(arguments.get("kind") or "")
        kind = EvidenceKind.CALL_CHAIN if trace_kind == "callers" else EvidenceKind.DATA_FLOW
    elif success and tool in {"impact", "file_dependencies", "explore"} and locations:
        kind = EvidenceKind.CALL_CHAIN
    strength = EvidenceStrength.MEDIUM if success else EvidenceStrength.WEAK
    if success and tool == "trace" and isinstance(payload, dict) and payload.get("partial_result"):
        strength = EvidenceStrength.PARTIAL
    summary = f"{_role_label(role)} Agent 自主调用 Atlas MCP `{tool}`" + (" 成功" if success else " 失败")
    if locations:
        summary += f"，提取位置 {len(locations)} 个"
    return CodeEvidence(
        evidence_id=evidence_id(finding_id, "agent-atlas", role.lower(), str(sequence), tool),
        kind=kind,
        strength=strength,
        summary=summary,
        source=f"agent-atlas-mcp:{role.lower()}",
        locations=locations[:16],
        data={
            "agent_atlas_tool": True,
            "mcp_tool": tool,
            "mcp_success": success,
            "arguments": arguments,
            "payload": _compact_agent_atlas_payload(payload),
            "raw": raw_text[:2000],
        },
    )


def _agent_atlas_tool_failure_evidence(
    finding_id: str,
    role: str,
    sequence: int,
    tool: str,
    arguments: Dict[str, Any],
    exc: BaseException,
) -> CodeEvidence:
    return CodeEvidence(
        evidence_id=evidence_id(finding_id, "agent-atlas", role.lower(), str(sequence), tool, "failed"),
        kind=EvidenceKind.TOOL_DIAGNOSTIC,
        strength=EvidenceStrength.WEAK,
        summary=f"{_role_label(role)} Agent 自主调用 Atlas MCP `{tool}` 失败：{exc}",
        source=f"agent-atlas-mcp:{role.lower()}",
        locations=_agent_atlas_argument_locations(tool, arguments),
        data={
            "agent_atlas_tool": True,
            "mcp_tool": tool,
            "mcp_success": False,
            "arguments": arguments,
            "error": str(exc),
        },
    )


def _agent_atlas_locations(payload: Any) -> List[SourceLocation]:
    locations: List[SourceLocation] = []
    seen: set[Tuple[str, Optional[int], Optional[int], Optional[str]]] = set()
    for value in _walk_values(payload):
        if not isinstance(value, dict):
            continue
        file = value.get("file") or value.get("file_path") or value.get("path") or value.get("relative_path")
        if not isinstance(file, str) or not file:
            continue
        line = _optional_int(value.get("line") or value.get("start_line") or value.get("startLine"))
        column = _optional_int(value.get("column") or value.get("start_column") or value.get("startColumn"))
        range_value = value.get("range")
        if isinstance(range_value, dict):
            start = range_value.get("start") or {}
            if isinstance(start, dict):
                line = line or _optional_int(start.get("line") or start.get("row"))
                column = column or _optional_int(start.get("column") or start.get("col"))
        symbol = value.get("qualified_name") or value.get("symbol") or value.get("name")
        location = SourceLocation(file=file, line=line, column=column, symbol=str(symbol) if symbol else None)
        marker = (location.file, location.line, location.column, location.symbol)
        if marker in seen:
            continue
        seen.add(marker)
        locations.append(location)
        if len(locations) >= 32:
            break
    return locations


def _agent_atlas_argument_locations(tool: str, arguments: Dict[str, Any]) -> List[SourceLocation]:
    if tool == "trace":
        file = arguments.get("file_path") or arguments.get("file") or arguments.get("path")
        line = _optional_int(arguments.get("line") or arguments.get("start_line"))
        column = _optional_int(arguments.get("column") or arguments.get("start_column"))
        if isinstance(file, str) and file:
            return [SourceLocation(file=file, line=line, column=column, symbol=str(arguments.get("symbol") or "") or None)]
    if tool == "file_dependencies":
        file = arguments.get("file_path")
        if isinstance(file, str) and file:
            return [SourceLocation(file=file)]
    return []


def _dedupe_agent_atlas_locations(locations: Sequence[SourceLocation]) -> List[SourceLocation]:
    result: List[SourceLocation] = []
    seen: set[Tuple[str, Optional[int], Optional[int], Optional[str]]] = set()
    for location in locations:
        marker = (location.file, location.line, location.column, location.symbol)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(location)
    return result


def _walk_values(value: Any) -> List[Any]:
    result: List[Any] = []
    stack = [value]
    while stack and len(result) < 800:
        current = stack.pop()
        result.append(current)
        if isinstance(current, dict):
            stack.extend(reversed([item for item in current.values() if isinstance(item, (dict, list))]))
        elif isinstance(current, list):
            stack.extend(reversed([item for item in current if isinstance(item, (dict, list))]))
    return result


def _compact_agent_atlas_payload(payload: Any) -> Any:
    text = json.dumps(payload, ensure_ascii=False, default=str)
    if len(text) <= 4000:
        return payload
    return {"truncated": True, "excerpt": text[:4000]}


def _compact_text(text: str, limit: int) -> str:
    normalized = " ".join(str(text or "").split())
    return normalized[:limit]


def _compact_agent_log_json(value: Any) -> str:
    return _compact_text(json.dumps(value, ensure_ascii=False, default=str), 600)


def _optional_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _stage_context(stage: str, prior: str, challenges: Sequence[str], extra: str) -> str:
    challenge_text = "\n".join(f"- {item}" for item in challenges) if challenges else "- 暂无已知阻断性质疑。"
    parts = [f"阶段：{stage}", f"已知质疑：\n{challenge_text}"]
    if prior:
        parts.append(prior)
    if extra:
        parts.append(extra)
    return "\n\n".join(parts)


def _make_debate_turn(
    role: DebateRole,
    round_index: int,
    claim: str,
    evidence_ids: Sequence[str],
    resolved: bool = False,
    decision: Optional[DebateDecision] = None,
    unresolved: Sequence[str] = (),
) -> DebateTurn:
    raw_claim = str(claim or "").strip()
    unique_evidence_ids = list(dict.fromkeys(str(item) for item in evidence_ids if str(item).strip()))
    structured = _structure_debate_turn(
        role=role,
        round_index=round_index,
        claim=raw_claim,
        evidence_ids=unique_evidence_ids,
        resolved=resolved,
        decision=decision,
        unresolved=unresolved,
    )
    return DebateTurn(
        role=role,
        round_index=round_index,
        claim=_render_structured_turn(structured),
        evidence_ids=unique_evidence_ids,
        resolved=resolved,
        structured=structured,
        raw_claim=raw_claim,
    )


def _structure_debate_turn(
    role: DebateRole,
    round_index: int,
    claim: str,
    evidence_ids: Sequence[str],
    resolved: bool,
    decision: Optional[DebateDecision],
    unresolved: Sequence[str],
) -> Dict[str, Any]:
    label = _extract_conclusion_label(claim)
    if not label and decision is not None:
        label = _verdict_label(decision.verdict)
    summary_segments = _clean_statement_segments(claim, max_segments=3, label=label)
    if not summary_segments:
        summary_segments = _fallback_turn_segments(claim, max_segments=2)
    key_points = _extract_turn_marked_lines(
        claim,
        (
            "确认",
            "已",
            "存在",
            "支持",
            "形成",
            "闭环",
            "可解析",
            "未发现针对报告路径的防护",
        ),
        limit=3,
    )
    gaps = _merge_challenges(
        list(unresolved),
        _extract_turn_marked_lines(
            claim,
            (
                "未",
                "缺少",
                "缺乏",
                "无法",
                "不能",
                "不足",
                "断链",
                "存疑",
                "不可达",
                "跳跃",
                "复读",
                "质疑",
                "限制",
                "需要补",
            ),
            limit=4,
        ),
    )
    return {
        "role": role.value,
        "role_label": _role_label(role.value),
        "round_index": round_index,
        "position": label,
        "resolved": resolved,
        "summary": " ".join(summary_segments).strip()[:700],
        "key_points": key_points,
        "unresolved": gaps[:5],
        "evidence_ids": list(evidence_ids)[:16],
        "raw_length": len(claim),
    }


def _render_structured_turn(structured: Dict[str, Any]) -> str:
    role_label = structured.get("role_label") or _role_label(str(structured.get("role") or ""))
    round_index = structured.get("round_index")
    lines = [f"## {role_label}第 {round_index} 回合摘要"]
    position = str(structured.get("position") or "").strip()
    if position:
        lines.append(f"结论倾向：{position}")
    lines.append("状态：" + ("已闭环或进入主持人总结" if structured.get("resolved") else "仍需验证"))
    summary = str(structured.get("summary") or "").strip()
    if summary:
        lines.extend(["核心陈述：", f"- {summary}"])
    key_points = [str(item).strip() for item in structured.get("key_points") or [] if str(item).strip()]
    if key_points:
        lines.append("已支持要点：")
        lines.extend(f"- {item}" for item in key_points[:3])
    unresolved = [str(item).strip() for item in structured.get("unresolved") or [] if str(item).strip()]
    if unresolved:
        lines.append("未闭环点：")
        lines.extend(f"- {item}" for item in unresolved[:5])
    evidence_ids = [str(item).strip() for item in structured.get("evidence_ids") or [] if str(item).strip()]
    if evidence_ids:
        suffix = " 等" if len(evidence_ids) > 10 else ""
        lines.append("引用证据：" + ", ".join(evidence_ids[:10]) + suffix)
    return "\n".join(lines)


def _turn_prompt_text(turn: DebateTurn) -> str:
    return turn.raw_claim if turn.raw_claim is not None else turn.claim


def _extract_conclusion_label(text: str) -> str:
    for label in FINAL_LABELS:
        if f"【{label}】" in text:
            return label
    normalized = re.sub(r"\s+", "", str(text or ""))
    for label in FINAL_LABELS:
        if re.search(rf"(?:结论|标签|方向|倾向)[:：]?{re.escape(label)}", normalized):
            return label
    return ""


def _fallback_turn_segments(text: str, max_segments: int) -> List[str]:
    segments: List[str] = []
    for raw_line in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = _strip_response_line(raw_line)
        if not line or _looks_like_task_echo(line):
            continue
        if len(line) < 8:
            continue
        segments.append(line[:260])
        if len(segments) >= max_segments:
            break
    return segments


def _extract_turn_marked_lines(text: str, markers: Sequence[str], limit: int) -> List[str]:
    lines: List[str] = []
    seen = set()
    for raw_line in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = _strip_response_line(raw_line)
        if not line:
            continue
        normalized = re.sub(r"\s+", "", line.lower())
        has_marker = any(marker.lower() in normalized for marker in markers)
        if not has_marker:
            continue
        if _looks_like_task_echo(line) and "复读" not in normalized:
            continue
        key = normalized[:120]
        if key in seen:
            continue
        seen.add(key)
        lines.append(line[:240])
        if len(lines) >= limit:
            break
    return lines


def _build_verification_case(bundle: EvidenceBundle) -> VerificationCase:
    finding = bundle.finding
    source_terms = _evidence_data_terms(bundle.evidence, "source_terms")
    sink_terms = _evidence_data_terms(bundle.evidence, "sink_terms")
    symbols = _evidence_data_terms(bundle.evidence, "symbols")
    primary_location = getattr(finding, "primary_location", None)
    if primary_location is None:
        locations = getattr(finding, "locations", []) or []
        primary_location = locations[0] if locations else None
    reported_location = primary_location.display() if primary_location else ""
    expected_path = _finding_code_flow_path(getattr(finding, "code_flows", []) or []) or _evidence_flow_path(bundle.evidence)
    dangerous_function = sink_terms[0] if sink_terms else symbols[0] if symbols else ""
    return VerificationCase(
        vulnerability_type=str(getattr(finding, "rule_id", "") or ""),
        reported_message=str(getattr(finding, "message", "") or ""),
        reported_location=reported_location,
        reported_source=", ".join(source_terms[:5]),
        reported_sink=", ".join(sink_terms[:5]),
        dangerous_function=dangerous_function,
        expected_attack_path=expected_path,
        required_proof=[
            "报告位置能解析到当前源码树中的真实代码。",
            "外部输入、文件输入、网络报文、命令行参数、消息载荷或内部接口能够到达漏洞相关函数。",
            "攻击者可控数据能够沿调用链或数据流传递到危险汇点。",
            "代码上下文业务逻辑支持变量语义、危险操作和影响归因。",
            "不存在已证实能覆盖该报告路径的防护消减措施。",
        ],
    )


def _verification_case_prompt(case: VerificationCase) -> str:
    lines = [
        f"- 漏洞类型/规则：{case.vulnerability_type or '未知'}",
        f"- 报告消息：{case.reported_message or '未知'}",
        f"- 报告位置：{case.reported_location or '未知'}",
        f"- 报告源点：{case.reported_source or '未提取'}",
        f"- 报告汇点/危险函数：{case.reported_sink or case.dangerous_function or '未提取'}",
        f"- 报告期望路径：{case.expected_attack_path or '未提供 codeFlow'}",
        "- 必须闭环的证明要件：",
    ]
    lines.extend(f"  - {item}" for item in case.required_proof)
    return "\n".join(lines)


def _build_verification_scorecard(
    evidence: Sequence[CodeEvidence], decision: Optional[DebateDecision]
) -> VerificationScorecard:
    source_location = _source_location_score(evidence)
    entry_reachability = _entry_reachability_score(evidence)
    call_chain = _call_chain_score(evidence)
    data_flow = _data_flow_score(evidence)
    controllability = _controllability_score(evidence, entry_reachability)
    protection = "candidate" if _has_protection(evidence) else "none"
    impact = _impact_score(evidence)
    rationale = _scorecard_rationale(
        source_location,
        entry_reachability,
        call_chain,
        data_flow,
        controllability,
        protection,
        impact,
    )
    if decision is None:
        return VerificationScorecard(
            source_location=source_location,
            entry_reachability=entry_reachability,
            call_chain=call_chain,
            data_flow=data_flow,
            controllability=controllability,
            protection=protection,
            impact=impact,
            confidence=_heuristic_scorecard_confidence(
                source_location,
                entry_reachability,
                call_chain,
                data_flow,
                controllability,
                impact,
            ),
            rationale=rationale,
        )
    return VerificationScorecard(
        source_location=source_location,
        entry_reachability=entry_reachability,
        call_chain=call_chain,
        data_flow=data_flow,
        controllability=controllability,
        protection=protection,
        impact=impact,
        verdict_label=_verdict_label(decision.verdict),
        confidence=round(float(decision.confidence or 0.0), 2),
        rationale=rationale,
    )


def _scorecard_prompt(scorecard: VerificationScorecard) -> str:
    lines = [
        f"- 源码定位：{_status_label(scorecard.source_location)}",
        f"- 入口可达：{_status_label(scorecard.entry_reachability)}",
        f"- 调用链：{_status_label(scorecard.call_chain)}",
        f"- 数据流：{_status_label(scorecard.data_flow)}",
        f"- 输入可控性：{_status_label(scorecard.controllability)}",
        f"- 防护消减：{_status_label(scorecard.protection)}",
        f"- 影响归因：{_status_label(scorecard.impact)}",
    ]
    if scorecard.rationale:
        lines.append("- 当前阻断/支撑理由：" + "；".join(scorecard.rationale[:5]))
    return "\n".join(lines)


def _build_evidence_ledger(
    evidence: Sequence[CodeEvidence], scorecard: VerificationScorecard
) -> List[EvidenceLedgerItem]:
    return [
        _ledger_item(
            "ledger-source-location",
            "source_location",
            "报告位置解析到当前源码树",
            scorecard.source_location,
            _items_by_kind(evidence, EvidenceKind.SOURCE_ROOT, EvidenceKind.SOURCE_LOCATION),
        ),
        _ledger_item(
            "ledger-entry-reachability",
            "entry_reachability",
            "存在外部/内部接口或输入源能够触发漏洞函数",
            scorecard.entry_reachability,
            _items_matching_entry(evidence),
        ),
        _ledger_item(
            "ledger-call-chain",
            "call_chain",
            "调用链能从入口或上游调用方串到报告函数",
            scorecard.call_chain,
            _items_by_kind(evidence, EvidenceKind.CALL_CHAIN, EvidenceKind.SARIF_CODE_FLOW),
        ),
        _ledger_item(
            "ledger-data-flow",
            "data_flow",
            "攻击者可控数据能到达危险汇点",
            scorecard.data_flow,
            _items_by_kind(evidence, EvidenceKind.DATA_FLOW, EvidenceKind.SARIF_CODE_FLOW),
        ),
        _ledger_item(
            "ledger-controllability",
            "controllability",
            "源点或参数具备攻击者可控性",
            scorecard.controllability,
            _items_matching_source_terms(evidence),
        ),
        _ledger_item(
            "ledger-business-context",
            "business_context",
            "代码上下文支持变量语义和业务目的判断",
            "confirmed" if _business_logic_operations(evidence) else "candidate" if _has_source_context(evidence) else "missing",
            _items_by_kind(evidence, EvidenceKind.SOURCE_LOCATION, EvidenceKind.DATA_FLOW, EvidenceKind.CALL_CHAIN),
        ),
        _ledger_item(
            "ledger-protection",
            "protection",
            "源码或项目知识中存在能影响该路径的防护消减证据",
            scorecard.protection,
            _items_by_kind(evidence, EvidenceKind.PROTECTION, EvidenceKind.PROJECT_CONTEXT),
        ),
        _ledger_item(
            "ledger-impact",
            "impact",
            "影响已关联到资产、权限边界或危险汇点",
            scorecard.impact,
            _items_by_kind(evidence, EvidenceKind.IMPACT, EvidenceKind.PROJECT_CONTEXT),
        ),
    ]


def _decision_with_scorecard_summary(decision: DebateDecision, scorecard: VerificationScorecard) -> DebateDecision:
    if decision.reasoning_summary and not _looks_like_task_echo(decision.reasoning_summary):
        return decision
    summary = "；".join(scorecard.rationale[:4]) or decision.reasoning_summary
    return DebateDecision(
        verdict=decision.verdict,
        confidence=decision.confidence,
        disputed_points=decision.disputed_points,
        reasoning_summary=summary,
        recommended_next_steps=decision.recommended_next_steps,
    )


def _evidence_data_terms(evidence: Sequence[CodeEvidence], key: str) -> List[str]:
    terms: List[str] = []
    for item in evidence:
        value = item.data.get(key)
        if isinstance(value, (list, tuple, set)):
            terms.extend(str(entry).strip() for entry in value if str(entry).strip())
        elif value not in (None, "", [], {}):
            terms.append(str(value).strip())
    return list(dict.fromkeys(term for term in terms if term))[:12]


def _finding_code_flow_path(code_flows: Sequence[Sequence[SourceLocation]]) -> str:
    for code_flow in code_flows:
        locations = [location.display() for location in code_flow if location]
        if locations:
            return " -> ".join(locations[:12])
    return ""


def _evidence_flow_path(evidence: Sequence[CodeEvidence]) -> str:
    for item in evidence:
        if item.kind not in {EvidenceKind.SARIF_CODE_FLOW, EvidenceKind.DATA_FLOW, EvidenceKind.CALL_CHAIN}:
            continue
        locations = [location.display() for location in item.locations if location]
        if locations:
            return " -> ".join(locations[:12])
    return ""


def _source_location_score(evidence: Sequence[CodeEvidence]) -> str:
    if _all_primary_locations_invalid(evidence):
        return "invalid"
    if _has_valid_location(evidence):
        return "confirmed"
    if _has_source_root(evidence):
        return "candidate"
    return "missing"


def _entry_reachability_score(evidence: Sequence[CodeEvidence]) -> str:
    if _has_entry_reachability(evidence):
        return "confirmed"
    if _has_meaningful_flow(evidence):
        return "candidate"
    return "missing"


def _call_chain_score(evidence: Sequence[CodeEvidence]) -> str:
    if any(
        item.kind == EvidenceKind.CALL_CHAIN
        and item.strength in {EvidenceStrength.STRONG, EvidenceStrength.MEDIUM}
        and item.source != "code-search"
        for item in evidence
    ):
        return "confirmed"
    if any(item.kind in {EvidenceKind.CALL_CHAIN, EvidenceKind.SARIF_CODE_FLOW} for item in evidence):
        return "candidate"
    return "missing"


def _data_flow_score(evidence: Sequence[CodeEvidence]) -> str:
    if any(
        item.kind in {EvidenceKind.DATA_FLOW, EvidenceKind.SARIF_CODE_FLOW}
        and item.strength in {EvidenceStrength.STRONG, EvidenceStrength.MEDIUM}
        and item.source != "code-search"
        for item in evidence
    ):
        return "confirmed"
    if _has_weak_source_sink(evidence) or any(item.kind == EvidenceKind.DATA_FLOW for item in evidence):
        return "candidate"
    return "missing"


def _controllability_score(evidence: Sequence[CodeEvidence], entry_reachability: str) -> str:
    if entry_reachability == "confirmed" and _items_matching_source_terms(evidence):
        return "confirmed"
    if _items_matching_source_terms(evidence) or entry_reachability == "candidate":
        return "candidate"
    return "missing"


def _impact_score(evidence: Sequence[CodeEvidence]) -> str:
    if any(item.kind == EvidenceKind.IMPACT for item in evidence):
        return "confirmed"
    if any(item.kind == EvidenceKind.PROJECT_CONTEXT for item in evidence):
        return "candidate"
    return "missing"


def _scorecard_rationale(
    source_location: str,
    entry_reachability: str,
    call_chain: str,
    data_flow: str,
    controllability: str,
    protection: str,
    impact: str,
) -> List[str]:
    rationale: List[str] = []
    if source_location == "invalid":
        rationale.append("报告位置未能映射到当前源码，源码真实性不成立。")
    elif source_location == "confirmed":
        rationale.append("报告位置已解析到当前源码。")
    else:
        rationale.append("报告位置尚未被强证据确认。")
    if entry_reachability != "confirmed":
        rationale.append("入口可达性未闭环，需要证明外部输入或内部接口能调用到漏洞函数。")
    if call_chain != "confirmed":
        rationale.append("调用链未达到强确认状态，需要补齐上游调用方到报告函数的连续路径。")
    if data_flow != "confirmed":
        rationale.append("源到汇数据流未达到强确认状态，需要证明可控数据传递到危险汇点。")
    if controllability == "missing":
        rationale.append("攻击者输入可控性缺少证据。")
    if protection == "candidate":
        rationale.append("存在防护候选证据，需要判断是否覆盖报告路径。")
    if impact == "missing":
        rationale.append("影响尚未关联到资产、权限边界或可达危险汇点。")
    if (
        source_location == "confirmed"
        and entry_reachability == "confirmed"
        and call_chain == "confirmed"
        and data_flow == "confirmed"
        and impact in {"confirmed", "candidate"}
        and protection == "none"
    ):
        rationale.append("源码定位、入口可达、调用链、数据流和影响证据已形成当前自动研判闭环。")
    return list(dict.fromkeys(rationale))[:8]


def _heuristic_scorecard_confidence(
    source_location: str,
    entry_reachability: str,
    call_chain: str,
    data_flow: str,
    controllability: str,
    impact: str,
) -> float:
    values = [source_location, entry_reachability, call_chain, data_flow, controllability, impact]
    score = 0.0
    for value in values:
        if value == "confirmed":
            score += 1.0
        elif value == "candidate":
            score += 0.5
    return round(min(0.95, score / max(1, len(values))), 2)


def _status_label(status: str) -> str:
    labels = {
        "confirmed": "已确认",
        "candidate": "候选/部分",
        "missing": "缺失",
        "invalid": "无效",
        "none": "未发现",
        "blocks": "已阻断",
    }
    return labels.get(status, status or "未知")


def _ledger_item(
    item_id: str,
    item_type: str,
    claim: str,
    status: str,
    evidence_items: Sequence[CodeEvidence],
) -> EvidenceLedgerItem:
    evidence_ids = [item.evidence_id for item in evidence_items if item.evidence_id]
    return EvidenceLedgerItem(
        id=item_id,
        type=item_type,
        claim=claim,
        status=status,
        source=_ledger_source(evidence_items),
        location=_ledger_location(evidence_items),
        confidence=_ledger_confidence(status),
        evidence_ids=list(dict.fromkeys(evidence_ids))[:12],
    )


def _ledger_source(evidence_items: Sequence[CodeEvidence]) -> str:
    sources = list(dict.fromkeys(item.source for item in evidence_items if item.source))
    return ", ".join(sources[:4]) if sources else "not-collected"


def _ledger_location(evidence_items: Sequence[CodeEvidence]) -> str:
    for item in evidence_items:
        if item.locations:
            return item.locations[0].display()
    return ""


def _ledger_confidence(status: str) -> float:
    values = {
        "confirmed": 0.85,
        "candidate": 0.55,
        "missing": 0.15,
        "invalid": 0.05,
        "none": 0.5,
        "blocks": 0.8,
    }
    return values.get(status, 0.3)


def _items_by_kind(evidence: Sequence[CodeEvidence], *kinds: EvidenceKind) -> List[CodeEvidence]:
    accepted = set(kinds)
    return [item for item in evidence if item.kind in accepted]


def _items_matching_entry(evidence: Sequence[CodeEvidence]) -> List[CodeEvidence]:
    matched = []
    for item in evidence:
        text = _evidence_item_text(item).lower()
        if any(marker.lower() in text for marker in ENTRY_REACHABILITY_MARKERS):
            matched.append(item)
    return matched


def _items_matching_source_terms(evidence: Sequence[CodeEvidence]) -> List[CodeEvidence]:
    matched = []
    for item in evidence:
        if item.data.get("source_terms"):
            matched.append(item)
            continue
        text = _evidence_item_text(item).lower()
        if any(marker.lower() in text for marker in ("request", "param", "query", "body", "stdin", "argv", "recv", "用户输入", "请求参数")):
            matched.append(item)
    return matched


def _evidence_item_text(item: CodeEvidence) -> str:
    parts = [item.summary, item.source]
    if item.snippet:
        parts.append(item.snippet[:2000])
    for location in item.locations[:10]:
        parts.append(location.display())
        if location.symbol:
            parts.append(location.symbol)
    parts.extend(_string_fragments(item.data))
    return "\n".join(part for part in parts if part)


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
        markdown_report = _markdown_report_prompt_text(item)
        if markdown_report:
            lines.append("  报告正文：\n```markdown\n" + markdown_report + "\n```")
        elif item.snippet and snippet_count < 8:
            lines.append("  代码片段：\n```text\n" + item.snippet[:1200] + "\n```")
            snippet_count += 1
        data_excerpt = _data_excerpt(item)
        if data_excerpt:
            lines.append("  数据：" + data_excerpt)
    if len(evidence) > 30:
        lines.append(f"- 另有 {len(evidence) - 30} 条证据未展开。")
    return "\n".join(lines) if lines else "无证据。"


def _markdown_report_prompt_text(item: CodeEvidence) -> str:
    if item.kind != EvidenceKind.REPORT:
        return ""
    if item.data.get("source_format") != "markdown":
        return ""
    text = str(item.data.get("markdown_report") or item.snippet or "").strip()
    if not text:
        return ""
    if len(text) <= MARKDOWN_REPORT_PROMPT_CHARS:
        return text
    return text[:MARKDOWN_REPORT_PROMPT_CHARS] + "\n\n[报告正文过长，以上为前 20000 字；完整正文保存在 REPORT 证据数据和临时 Markdown 文件中。]"


def _data_excerpt(item: CodeEvidence) -> str:
    keys = (
        "source_format",
        "source_report_format",
        "source_report",
        "temporary_markdown_report",
        "markdown_start_line",
        "markdown_end_line",
        "sarif_result_indices",
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
        "focus_path",
        "focus_path_facts",
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
        lines.append("- 未获得 Atlas 证据；需要确认 Atlas MCP 是否可启动，并优先尝试 v1.5+ Focus 查询；预热持久缓存只是可选优化。")
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


def _code_context_business_logic_report(evidence: Sequence[CodeEvidence]) -> str:
    if not _has_source_context(evidence):
        return "当前未收集到可审查的报告附近源码上下文；无法稳定说明漏洞代码的业务目的。"
    lines = []
    locations = _context_locations(evidence)
    if locations:
        lines.append("- 报告上下文位置：" + " -> ".join(locations[:8]))
    symbols = _context_symbols(evidence)
    if symbols:
        lines.append("- 相关符号/变量：" + ", ".join(symbols[:10]))
    operations = _business_logic_operations(evidence)
    if operations:
        lines.append("- 行为目的候选：" + "；".join(operations[:6]) + "。")
    else:
        lines.append("- 行为目的候选：当前证据只能确认报告附近源码被读取，尚不能稳定归纳业务目的。")
    sensitive_note = _sensitive_context_note(evidence)
    if sensitive_note:
        lines.append("- 敏感语义校验：" + sensitive_note)
    return "\n".join(lines)


def _attack_chain_report(bundle: EvidenceBundle) -> str:
    evidence = bundle.evidence
    steps = [
        f"1. 报告入口：`{bundle.finding.rule_id}` 指出 {bundle.finding.message}，对应输入报告证据 {_join_ids(_ids(evidence, EvidenceKind.REPORT))}。",
        "2. 源码定位：" + (_source_authenticity_report(evidence).replace("\n", "\n   ") or "未能定位真实源码。"),
        "3. 代码上下文业务目的：" + (_code_context_business_logic_report(evidence).replace("\n", "\n   ") or "未能归纳上下文业务逻辑。"),
        "4. 传播/调用路径：" + (_flow_report(evidence).replace("\n", "\n   ") or "未建立路径。"),
        "5. 危险操作或资产影响：" + _impact_assessment(evidence),
    ]
    if _has_protection(evidence):
        steps.append("6. 防护限制：路径附近存在防护证据，攻击链必须证明这些控制无法覆盖该输入。")
    else:
        steps.append("6. 防护限制：未发现针对报告路径的防护消减证据，本轮不引入防护消减假设。")
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


def _negative_autonomous_audit_context(bundle: EvidenceBundle) -> str:
    evidence = bundle.evidence
    lines = [
        "反方自主验证策略：不要只复述正方报告，应独立围绕原始报告验证源码真实性、代码上下文业务逻辑、可达入口、调用链、数据流、影响归因、防护和敏感信息语义。",
        "执行要求：先从 REPORT 和 SOURCE_LOCATION 证据确认报告是否被正确读取，再用 SARIF_CODE_FLOW、DATA_FLOW、CALL_CHAIN、TOOL_DIAGNOSTIC、源码片段和项目上下文交叉核对每个链路节点。",
        "Atlas/rg/源码审查要求：Atlas trace/calls/search、rg/grep 或源码阅读证据必须围绕报告路径、报告符号、codeFlow 或调用邻域；发现缺边、未命中、partial/empty 或无关候选时，应指出具体断点和还需要补的证据。",
        "质疑目标：寻找能推翻、削弱或限定正方主张的客观证据，包括业务逻辑说明与源码不符、不可达入口、同名但不同上下文的候选命中、死代码/测试代码、数据流断链、汇点不可控、影响无法直接归因、明确防护覆盖或敏感信息语义未证实。",
    ]
    if _has_meaningful_flow(evidence):
        lines.append("当前已有调用链/数据流候选，反方应逐跳核对同版本、同函数上下文、参数是否连续传递，并检查是否存在跳过的中间节点。")
    else:
        lines.append("当前缺少强调用链/数据流证据，反方应优先要求补齐从外部输入源头到报告危险点的可审计路径。")
    if _has_protection(evidence):
        lines.append("当前存在防护候选证据，反方应审查这些控制是否覆盖报告路径；只能基于已有证据质疑，不能凭空假设统一防护。")
    if _sensitive_info_candidates(evidence):
        lines.append("当前存在敏感信息候选词，反方必须先判断变量或参数是否真实敏感，例如 key 是密钥还是普通标识。")
    return "\n".join(lines)


def _moderator_autonomous_review_context(
    bundle: EvidenceBundle, turns: Sequence[DebateTurn], candidate_unresolved: Sequence[str]
) -> str:
    evidence = bundle.evidence
    lines = [
        "Moderator 自主审查策略：不要只摘要双方文本，应独立审查报告读取、证据链闭环、争议质量和流程是否需要继续。",
        "审查顺序：REPORT 是否包含具体漏洞类型/消息/位置；SOURCE_LOCATION 是否解析到真实源码；代码上下文业务逻辑说明是否能由源码复现；CALL_CHAIN/DATA_FLOW/SARIF_CODE_FLOW 是否能串起入口、传播节点和汇点；IMPACT/PROJECT_CONTEXT 是否支持影响；PROTECTION 和敏感信息语义是否有证据。",
        "回合控制：如果正反方复读、引用提示词、引用无关命中或没有新增证据，应提前结束并给出结论；如果仍有影响结论的断链、异常报告读取或关键证据缺口，应要求继续下一轮并列出具体缺口。",
        "中立约束：只能基于已有证据 ID 和双方陈述裁定，不替任一方补造事实；可以指出哪一方没有达成自己的目标。",
    ]
    if _all_primary_locations_invalid(evidence):
        lines.append("当前报告主位置未能解析到源码，Moderator 应重点审查是否为报告路径/源码根配置问题或报告读取异常。")
    if not _has_meaningful_flow(evidence):
        lines.append("当前缺少强调用链/数据流证据，Moderator 应把端到端路径作为优先未闭环争议。")
    if _sensitive_info_candidates(evidence):
        lines.append("当前存在敏感信息候选词，Moderator 应检查反方是否审查真实敏感性，正方是否证明泄露或可读路径。")
    repeated_roles = _roles_with_repeated_turns(turns)
    if repeated_roles:
        lines.append("当前检测到可能复读角色：" + "、".join(repeated_roles) + "；Moderator 应判断是否提前停止。")
    if candidate_unresolved:
        lines.append("候选未闭环争议需要逐项裁定：" + "；".join(_clean_dispute_line(item) for item in candidate_unresolved[:6] if _clean_dispute_line(item)))
    return "\n".join(lines)


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


def _negative_business_logic_challenge(evidence: Sequence[CodeEvidence]) -> str:
    report = _code_context_business_logic_report(evidence)
    if not _has_source_context(evidence):
        return report + "\n- 反方核验：缺少报告附近源码上下文时，不能用变量名、规则名或孤立汇点推断业务语义。"
    lines = [report]
    lines.append("- 反方核验：正方的业务逻辑说明必须能从报告附近源码、codeFlow、调用链或数据流证据中复现，不能脱离当前代码上下文泛化。")
    if _sensitive_info_candidates(evidence):
        lines.append("- 反方核验：敏感信息类结论必须结合上下文行为判断；若没有加解密、签名、凭证校验、返回、日志或存储路径，变量名本身不足以证明敏感性。")
    return "\n".join(lines)


def _negative_sensitive_info_challenge(evidence: Sequence[CodeEvidence]) -> str:
    candidates = _sensitive_info_candidates(evidence)
    if not candidates:
        return "当前报告与证据链未呈现敏感信息类变量、参数或资产；反方不额外引入敏感信息假设。"
    labels = _candidate_labels(candidates)
    label_text = "、".join(labels[:8])
    has_key = any(label == "key" for label, _explicit in candidates)
    has_explicit = any(explicit for _label, explicit in candidates)
    if has_key and not has_explicit:
        return (
            f"报告/源码证据出现 {label_text}，但 key 可能为密钥，也可能只是普通标识、索引或业务字段；"
            "正方必须用证据证明其真实敏感性，确认其确实承载密钥、凭证、token、密码等敏感信息，并说明泄露或可读路径。"
            + " "
            + _sensitive_context_note(evidence)
        )
    if has_key:
        return (
            f"报告/源码证据出现 {label_text}。即便存在敏感信息候选词，key 仍需先区分密钥与普通标识；"
            "反方应核验变量来源、用途、传输/日志/响应/持久化路径和权限边界，只有证明真实敏感性后才能支持敏感信息泄露影响。"
            + " "
            + _sensitive_context_note(evidence)
        )
    return (
        f"报告/源码证据出现 {label_text}。反方应核验证据链是否证明这些参数或变量真实承载密钥、凭证、token、密码等敏感信息，"
        "以及是否存在可观察的泄露、写出或未授权读取路径。"
    )


def _negative_impact_challenge(evidence: Sequence[CodeEvidence]) -> str:
    impacts = [item for item in evidence if item.kind in {EvidenceKind.IMPACT, EvidenceKind.PROJECT_CONTEXT}]
    if not impacts:
        return "未看到价值资产、权限边界或业务影响证据，不能扩大影响。"
    return "影响只能归因于漏洞技术路径本身；不得把社会工程、凭证窃取后的横向移动等后续非直接路径计入直接影响。"


def _clarification_for_challenge(evidence: Sequence[CodeEvidence], challenge: str) -> str:
    if "源码" in challenge or "位置" in challenge or "解析" in challenge:
        return "源码真实性依据为：" + _source_authenticity_report(evidence)
    if "业务逻辑" in challenge or "行为目的" in challenge or "上下文语义" in challenge:
        return _code_context_business_logic_report(evidence)
    if "数据流" in challenge or "调用" in challenge or "路径" in challenge:
        return _flow_report(evidence)
    if "防护" in challenge or "校验" in challenge or "鉴权" in challenge or "消毒" in challenge:
        return _protection_assessment(evidence)
    if _is_sensitive_info_challenge(challenge):
        return _sensitive_info_assessment(evidence)
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
    if "业务逻辑" in challenge or "行为目的" in challenge or "上下文语义" in challenge:
        return not _has_source_context(evidence)
    if "数据流" in challenge or "调用" in challenge or "路径" in challenge or "尚未建立" in challenge:
        return not _has_meaningful_flow(evidence)
    if "防护" in challenge:
        return _has_protection(evidence)
    if _is_sensitive_info_challenge(challenge):
        return not _has_explicit_sensitive_info_evidence(evidence)
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
    latest_text = _normalize_claim_for_repetition(_turn_prompt_text(latest))
    if len(latest_text) < 24:
        return None
    for previous in turns[:-1]:
        if previous.role == DebateRole.MODERATOR:
            continue
        previous_text = _normalize_claim_for_repetition(_turn_prompt_text(previous))
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


def _roles_with_repeated_turns(turns: Sequence[DebateTurn]) -> List[str]:
    repeated: List[str] = []
    seen = set()
    for index, turn in enumerate(turns):
        if turn.role == DebateRole.MODERATOR:
            continue
        current = _normalize_claim_for_repetition(_turn_prompt_text(turn))
        if len(current) < 24:
            continue
        for previous in turns[:index]:
            if previous.role != turn.role:
                continue
            previous_text = _normalize_claim_for_repetition(_turn_prompt_text(previous))
            if len(previous_text) < 24:
                continue
            similarity = difflib.SequenceMatcher(None, current, previous_text).ratio()
            contains_repetition = min(len(current), len(previous_text)) >= 80 and (
                current in previous_text or previous_text in current
            )
            if similarity >= 0.88 or contains_repetition:
                role_label = _role_label(turn.role.value)
                if role_label not in seen:
                    repeated.append(role_label)
                    seen.add(role_label)
                break
    return repeated


def _normalize_claim_for_repetition(text: str) -> str:
    normalized = re.sub(r"`[^`]+`", "", text.lower())
    normalized = re.sub(r"\b[a-z]+-[0-9a-f]{8,}\b", "", normalized)
    normalized = re.sub(r"evidence[_-]?[a-z0-9_-]+", "", normalized)
    normalized = re.sub(r"[\s#*_>\-|:：,，.;；。!！?？()\[\]【】\"'“”‘’]+", "", normalized)
    return normalized


def _dedupe_debate_turns(turns: Sequence[DebateTurn]) -> List[DebateTurn]:
    deduped: List[DebateTurn] = []
    seen = set()
    for turn in turns:
        key = (turn.role.value, turn.round_index, re.sub(r"\s+", " ", turn.claim).strip())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(turn)
    return deduped


def _fallback_moderator_round_decision(
    base_decision: DebateDecision,
    candidate_unresolved: Sequence[str],
    *,
    round_index: int,
    reached_round_limit: bool,
    repetition_issue: Optional[str],
) -> ModeratorRoundDecision:
    unresolved = _merge_challenges(candidate_unresolved)
    if repetition_issue:
        return ModeratorRoundDecision(
            continue_debate=False,
            unresolved=unresolved,
            summary=_moderator_round_summary(
                round_index,
                False,
                unresolved,
                f"检测到复读：{repetition_issue}；继续辩论不会增加新证据，进入最终总结。",
            ),
        )
    if reached_round_limit:
        return ModeratorRoundDecision(
            continue_debate=False,
            unresolved=unresolved,
            summary=_moderator_round_summary(
                round_index,
                False,
                unresolved,
                "已达到预设轮数，本轮正反方交锋后由 Moderator 进入最终总结。",
            ),
        )
    if _can_reach_consensus(base_decision, unresolved):
        return ModeratorRoundDecision(
            continue_debate=False,
            unresolved=[],
            summary=_moderator_round_summary(
                round_index,
                False,
                [],
                "正反方本轮未保留阻断性质疑，证据链已达到当前自动裁决所需闭环，进入最终总结。",
            ),
        )
    if _material_unresolved(unresolved):
        return ModeratorRoundDecision(
            continue_debate=True,
            unresolved=unresolved,
            summary=_moderator_round_summary(
                round_index,
                True,
                unresolved,
                "本轮仍存在会影响结论的未闭环争议，需要正方继续补证或澄清，并由反方复审。",
            ),
        )
    return ModeratorRoundDecision(
        continue_debate=False,
        unresolved=unresolved,
        summary=_moderator_round_summary(
            round_index,
            False,
            unresolved,
            "剩余问题未构成继续辩论的阻断性质疑，进入最终总结。",
        ),
    )


def _parse_moderator_round_decision(
    text: Optional[str], fallback: ModeratorRoundDecision, candidate_unresolved: Sequence[str]
) -> Optional[ModeratorRoundDecision]:
    if not text or _looks_like_task_echo(text):
        return None
    summary = _clean_moderator_review_text(text)
    if not summary:
        return None
    continue_debate = _parse_continue_decision(summary, fallback.continue_debate)
    unresolved = _merge_challenges(candidate_unresolved, _negative_disputed_points(summary))
    if not continue_debate and not _material_unresolved(unresolved):
        unresolved = []
    if continue_debate and not unresolved:
        unresolved = list(fallback.unresolved)
    return ModeratorRoundDecision(
        continue_debate=continue_debate,
        unresolved=unresolved,
        summary=_ensure_moderator_decision_summary(summary, continue_debate, unresolved),
    )


def _parse_continue_decision(text: str, default: bool) -> bool:
    normalized = re.sub(r"\s+", "", text.lower())
    negative_patterns = (
        "是否继续下一轮:否",
        "是否继续下一轮：否",
        "继续下一轮:否",
        "继续下一轮：否",
        "是否继续:否",
        "是否继续：否",
        "不继续下一轮",
        "无需继续",
        "不需要继续",
        "停止继续",
        "进入最终总结",
        "进入结案",
    )
    if any(pattern in normalized for pattern in negative_patterns):
        return False
    positive_patterns = (
        "是否继续下一轮:是",
        "是否继续下一轮：是",
        "继续下一轮:是",
        "继续下一轮：是",
        "是否继续:是",
        "是否继续：是",
        "需要继续",
        "继续辩论",
        "继续下一轮",
    )
    if any(pattern in normalized for pattern in positive_patterns):
        return True
    return default


def _clean_moderator_review_text(text: str) -> str:
    lines = []
    for raw_line in text.strip().splitlines():
        if _looks_like_task_echo(raw_line):
            continue
        cleaned = raw_line.replace("**", "").strip()
        if cleaned:
            lines.append(cleaned)
    return "\n".join(lines).strip()[:1200]


def _ensure_moderator_decision_summary(text: str, continue_debate: bool, unresolved: Sequence[str]) -> str:
    if re.search(r"是否继续(?:下一轮|辩论)?\s*[:：]", text):
        return text
    return "\n".join(
        [
            "## Moderator 回合分析",
            f"是否继续下一轮：{'是' if continue_debate else '否'}",
            "未闭环争议：",
            _challenge_lines(unresolved),
            "分析：",
            text,
        ]
    )


def _append_moderator_limit_notice(summary: str, round_index: int) -> str:
    notice = f"已达到第 {round_index} 个可交锋回合，本轮后由 Moderator 进入最终总结。"
    if notice in summary:
        return summary
    return summary.rstrip() + "\n\n" + notice


def _moderator_round_summary(round_index: int, continue_debate: bool, unresolved: Sequence[str], analysis: str) -> str:
    return "\n".join(
        [
            f"## Moderator 第 {round_index} 回合分析",
            f"是否继续下一轮：{'是' if continue_debate else '否'}",
            "未闭环争议：",
            _challenge_lines(unresolved),
            "分析：",
            analysis,
        ]
    )


def _challenge_lines(challenges: Sequence[str]) -> str:
    items = [str(item).strip() for item in challenges if str(item).strip()]
    if not items:
        return "- 无"
    return "\n".join(f"- {item}" for item in items[:8])


def _clean_moderator_summary(text: str) -> str:
    segments = _clean_statement_segments(text, max_segments=5)
    statement = " ".join(segments).strip()
    if not statement or _looks_like_task_echo(statement):
        return ""
    return statement[:1000]


def _clean_statement_segments(text: str, max_segments: int, label: str = "") -> List[str]:
    segments: List[str] = []
    for raw_line in text.strip().splitlines():
        if _looks_like_task_echo(raw_line):
            continue
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
    cleaned = text.replace("**", "").strip("# -*\t ，,;；")
    cleaned = re.sub(r"^\s*(?:\d+[\.\、\)]\s*)+", "", cleaned)
    cleaned = re.sub(
        r"^\s*(?:分析用户请求|分析请求|请求分析|理解目标|分析输入|分析|思考|推理|reasoning|analysis)\s*[:：]\s*",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )
    labels = [label] if label else []
    labels.extend(item for item in FINAL_LABELS if item not in labels)
    label_pattern = "|".join(re.escape(item) for item in labels if item)
    if label_pattern:
        cleaned = re.sub(rf"^\s*(?:结论标签|结论|标签)\s*[:：]?\s*【?(?:{label_pattern})】?\s*[，,;；:：-]*\s*", "", cleaned)
        cleaned = re.sub(rf"^\s*【(?:{label_pattern})】\s*[，,;；:：-]*\s*", "", cleaned)
        cleaned = re.sub(rf"^\s*(?:{label_pattern})\s*[，,;；:：-]+\s*", "", cleaned)
    cleaned = re.sub(r"^\s*(?:结案陈述|结案陈词|陈述正文|正文|主持人总结|总结)\s*[:：]\s*", "", cleaned)
    cleaned = re.sub(r"^\s*(?:\d+[\.\、\)]\s*)+", "", cleaned)
    cleaned = re.sub(
        r"^\s*(?:分析用户请求|分析请求|请求分析|理解目标|分析输入|角色|任务|方向|约束|反方质疑摘要|分析|思考|推理|reasoning|analysis)\s*[:：]\s*",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )
    return cleaned.strip()


def _split_statement_segments(text: str) -> List[str]:
    parts = re.split(r"(?<=[。！？!?])\s*", text)
    return [part.strip() for part in parts if part.strip()]


def _looks_like_task_echo(statement: str) -> bool:
    normalized = re.sub(r"\s+", "", statement.lower())
    markers = (
        "用户要求",
        "用户请求",
        "任务要求",
        "根据任务要求",
        "分析用户请求",
        "理解目标",
        "分析输入",
        "用户希望我担任",
        "agent.md",
        "agent配置",
        "角色配置",
        "角色名称",
        "提示词",
        "系统提示",
        "systemprompt",
        "prompt",
        "开发者指令",
        "系统指令",
        "指令遵循",
        "禁止编造文件",
        "禁止编造",
        "每个具体论断",
        "输出必须使用中文markdown",
        "证据解释约束",
        "source_root只能证明",
        "rg/grep证据必须",
        "若存在atlas-agent-mcp",
        "围绕报告收集证据",
        "客观复核正方",
        "不得新增双方没有提出",
        "必须客观区分",
        "输出应简洁",
        "必须优先寻找新证据",
        "重新阅读源码上下文",
        "检查atlasproject/status",
        "用search/trace/calls补齐",
        "结论标签固定",
        "标签固定为",
        "标签约束",
        "强约束",
        "分析请求",
        "指令要求",
        "系统要求",
        "遵守这个标签",
        "必须遵守",
        "之前的分析",
        "即使我之前",
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
        "担任正方",
        "担任反方",
        "担任主持人",
        "affirmative_default",
        "positive_default",
        "negative_default",
        "moderator_default",
        "正方agent",
        "反方agent",
        "反方质疑摘要",
        "方向真实漏洞",
        "方向误报",
        "方向证据不足",
        "方向可达性存疑",
        "约束中文markdown",
        "引用证据id",
        "不重复指令",
        "坚持漏洞主张",
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


def _fallback_moderator_final_conclusion(
    bundle: EvidenceBundle, decision: DebateDecision, challenges: Sequence[str]
) -> str:
    label, statement = _fallback_moderator_label_statement(bundle, decision, challenges)
    return f"【{label}】，{statement}"


def _fallback_moderator_label_statement(
    bundle: EvidenceBundle, decision: DebateDecision, challenges: Sequence[str]
) -> Tuple[str, str]:
    evidence = bundle.evidence
    if _all_primary_locations_invalid(evidence):
        return "误报", "报告位置无法映射到当前源码版本，不能证明漏洞真实存在。"
    if _has_reachability_doubt(evidence):
        return (
            "可达性存疑",
            "局部源码或源汇路径存在，但未证明外部或内部 REST/API/接口入口能够调用到漏洞相关函数，需排除废弃代码或不可达路径。",
        )
    if decision.verdict == Verdict.TRUE_POSITIVE:
        if _has_meaningful_flow(evidence) and not _has_protection(evidence):
            return "真实漏洞", "报告、源码位置和数据流/调用链证据形成闭环，当前未识别到有效防护。"
        if _has_meaningful_flow(evidence) and _has_protection(evidence):
            return "真实漏洞", "攻击路径存在较强证据，但防护是否足以消减风险仍需重点验证。"
    if decision.verdict == Verdict.FALSE_POSITIVE:
        return "误报", decision.reasoning_summary
    if _has_protection(evidence) and not _has_meaningful_flow(evidence):
        return "误报", "缺少可验证攻击路径，且源码附近已有可能消减风险的控制。"
    if _has_protection(evidence) and not _material_unresolved(challenges):
        return "证据不足", "源码存在但端到端路径不足，且附近防护可能消减风险。"
    if _has_meaningful_flow(evidence):
        return "证据不足", "仍存在路径可达性、防护有效性或影响归因未闭环的问题。"
    return "证据不足", "当前只能确认部分源码或局部源汇迹象，尚未证明完整攻击链。"


def _ensure_moderator_final_label(text: Optional[str], decision: DebateDecision) -> str:
    cleaned = str(text or "").strip()
    if not cleaned:
        return f"【{_moderator_label_from_decision(decision)}】，{decision.reasoning_summary}"
    if _extract_conclusion_label(cleaned):
        return cleaned
    return f"【{_moderator_label_from_decision(decision)}】，{cleaned}"


def _moderator_label_from_decision(decision: DebateDecision) -> str:
    if decision.verdict == Verdict.INCONCLUSIVE:
        haystack = " ".join([decision.reasoning_summary, *decision.disputed_points])
        if any(marker in haystack for marker in ("可达", "入口", "接口", "REST", "API", "废弃代码", "死代码")):
            return "可达性存疑"
    return _verdict_label(decision.verdict)


def _verdict_from_final_label(label: str) -> Optional[Verdict]:
    if label == "真实漏洞":
        return Verdict.TRUE_POSITIVE
    if label == "误报":
        return Verdict.FALSE_POSITIVE
    if label in {"证据不足", "可达性存疑"}:
        return Verdict.INCONCLUSIVE
    return None


def _append_evidence_graph_markdown(conclusion: str, graph: Dict[str, Any]) -> str:
    graph_markdown = graph_to_markdown(graph).strip()
    if not graph_markdown:
        return conclusion
    if "### 证据串联图" in conclusion or "### 调用链 / 数据流概览" in conclusion:
        return conclusion
    return conclusion.rstrip() + "\n\n" + graph_markdown


def _conclusion_without_evidence_graph(conclusion: str) -> str:
    for marker in ("\n### 证据串联图", "\n### 调用链 / 数据流概览"):
        if marker in conclusion:
            return conclusion.split(marker, 1)[0].rstrip()
    if conclusion.startswith("### 证据串联图") or conclusion.startswith("### 调用链 / 数据流概览"):
        return ""
    return conclusion.rstrip()


def _decision_from_moderator_conclusion(base: DebateDecision, final_conclusion: str) -> DebateDecision:
    reasoning_summary = _clean_moderator_summary(_conclusion_without_evidence_graph(final_conclusion)) or base.reasoning_summary
    label = _extract_conclusion_label(final_conclusion)
    verdict = _verdict_from_final_label(label) or base.verdict
    disputed = list(base.disputed_points)
    if label == "可达性存疑" and not any("可达" in item or "入口" in item for item in disputed):
        disputed.append("主持人最终总结认为入口可达性仍未闭环。")
    return DebateDecision(
        verdict=verdict,
        confidence=base.confidence if verdict == base.verdict else min(base.confidence, 0.6),
        disputed_points=disputed if verdict == Verdict.INCONCLUSIVE else [],
        reasoning_summary=reasoning_summary,
        recommended_next_steps=base.recommended_next_steps,
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


def _has_reachability_doubt(evidence: Sequence[CodeEvidence]) -> bool:
    return _has_valid_location(evidence) and _has_local_vulnerability_evidence(evidence) and not _has_entry_reachability(evidence)


def _has_local_vulnerability_evidence(evidence: Sequence[CodeEvidence]) -> bool:
    if _has_meaningful_flow(evidence) or _has_weak_source_sink(evidence):
        return True
    return any(item.kind == EvidenceKind.DATA_FLOW and item.data.get("sink_terms") for item in evidence)


def _has_entry_reachability(evidence: Sequence[CodeEvidence]) -> bool:
    text = _entry_reachability_text(evidence)
    for marker in ENTRY_REACHABILITY_MARKERS:
        normalized = marker.lower()
        if not normalized:
            continue
        if re.search(r"^[a-z0-9_]+$", normalized):
            if re.search(rf"(?<![a-z0-9_]){re.escape(normalized)}(?![a-z0-9_])", text):
                return True
        elif normalized in text:
            return True
    return False


def _entry_reachability_text(evidence: Sequence[CodeEvidence]) -> str:
    chunks: List[str] = []
    for item in evidence:
        if item.kind in {EvidenceKind.REPORT, EvidenceKind.SOURCE_LOCATION, EvidenceKind.SARIF_CODE_FLOW, EvidenceKind.DATA_FLOW, EvidenceKind.CALL_CHAIN, EvidenceKind.PROJECT_CONTEXT}:
            chunks.append(item.summary)
        if item.snippet:
            chunks.append(item.snippet[:2000])
        for location in item.locations[:10]:
            chunks.append(location.file)
            if location.symbol:
                chunks.append(location.symbol)
        data = item.data or {}
        for key in ("source_terms", "symbols", "callers", "callees", "locations", "code_flows", "query_terms"):
            value = data.get(key)
            if value not in (None, "", [], {}):
                chunks.append(str(value)[:2000])
        raw_result = data.get("raw_result")
        if isinstance(raw_result, dict):
            chunks.append(str(raw_result.get("message", ""))[:1000])
            chunks.append(str(raw_result.get("locations", ""))[:1000])
    return "\n".join(chunk for chunk in chunks if chunk).lower()[:60000]


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


def _merge_challenges(*groups: Sequence[str]) -> List[str]:
    merged: List[str] = []
    seen = set()
    for group in groups:
        for item in group:
            cleaned = _clean_dispute_line(item)
            if not cleaned:
                continue
            key = re.sub(r"\s+", "", cleaned.lower())
            if key in seen:
                continue
            seen.add(key)
            merged.append(cleaned)
    return merged[:8]


def _negative_disputed_points(text: str) -> List[str]:
    disputes: List[str] = []
    for raw_line in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = _clean_dispute_line(raw_line)
        if not line or _is_negative_acceptance_line(line):
            continue
        if _is_negative_dispute_line(line):
            disputes.append(line)
    return _merge_challenges(disputes)


def _clean_dispute_line(text: str) -> str:
    cleaned = text.replace("**", "").strip()
    cleaned = re.sub(r"^\s*(?:[-*+>]\s*)+", "", cleaned)
    cleaned = re.sub(r"^\s*(?:\d+[\.\、\)]\s*)+", "", cleaned)
    cleaned = cleaned.strip("# \t，,;；")
    cleaned = re.sub(r"^\s*(?:仍未闭环的问题|待正方澄清的问题|反方阶段性意见|反方复审意见|是否继续质疑)\s*[:：]?\s*", "", cleaned)
    if cleaned in {"是", "否", "问题", "质疑", "分歧"}:
        return ""
    if cleaned.startswith("正方必须证明") and "否则结论应" in cleaned:
        return ""
    normalized = re.sub(r"\s+", "", cleaned.lower())
    if "不接受未引用证据id的新增事实" in normalized:
        return ""
    return cleaned[:240].strip()


def _is_negative_acceptance_line(text: str) -> bool:
    normalized = re.sub(r"\s+", "", text.lower())
    if "不接受" in normalized or "暂不接受" in normalized:
        return False
    acceptance_markers = (
        "暂未发现足以推翻",
        "暂无已知阻断性质疑",
        "暂未发现硬性反证",
        "未发现足以推翻",
        "不继续质疑",
        "无需继续质疑",
        "已经闭环",
        "已闭环",
        "可以闭环",
        "接受攻击链基本成立",
        "反方接受",
        "同意正方",
    )
    return any(marker in normalized for marker in acceptance_markers)


def _is_negative_dispute_line(text: str) -> bool:
    normalized = re.sub(r"\s+", "", text.lower())
    dispute_markers = (
        "仍未闭环",
        "未闭环",
        "无法证明",
        "未证明",
        "尚未证明",
        "不能证明",
        "无法确认",
        "未验证",
        "缺少",
        "缺乏",
        "证据不足",
        "不成立",
        "不可达",
        "断点",
        "跳跃",
        "无关命中",
        "混充证据",
        "浑水摸鱼",
        "误报",
        "不接受",
        "继续质疑",
        "存在分歧",
        "不同意",
        "不能支持",
        "无法支持",
        "遗漏",
        "死代码",
        "废弃代码",
        "可达性存疑",
        "入口可达性",
        "接口入口",
        "rest接口",
        "api入口",
        "普通标识",
        "真实敏感性",
        "是否敏感",
        "是否为密钥",
        "未证明敏感",
        "不能证明敏感",
        "无法证明敏感",
        "密钥也可能",
        "业务逻辑",
        "行为目的",
        "上下文语义",
        "上下文业务",
        "代码上下文",
    )
    return any(marker in normalized for marker in dispute_markers)


def _material_unresolved(challenges: Sequence[str]) -> bool:
    material = (
        "无法",
        "尚未建立",
        "未闭环",
        "无法证明",
        "未证明",
        "尚未证明",
        "不能证明",
        "无法确认",
        "未验证",
        "缺少",
        "缺乏",
        "证据不足",
        "不成立",
        "不可达",
        "断点",
        "跳跃",
        "不接受",
        "存在分歧",
        "不同意",
        "不能支持",
        "无法支持",
        "遗漏",
        "受限",
        "死代码",
        "废弃代码",
        "可达性存疑",
        "入口可达性",
        "接口入口",
        "rest接口",
        "api入口",
        "cannot be resolved",
        "No verified",
        "degraded",
        "outside configured",
        "普通标识",
        "真实敏感性",
        "是否敏感",
        "是否为密钥",
        "未证明敏感",
        "不能证明敏感",
        "无法证明敏感",
        "密钥也可能",
        "业务逻辑",
        "行为目的",
        "上下文语义",
        "上下文业务",
        "代码上下文",
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


def _sensitive_info_assessment(evidence: Sequence[CodeEvidence]) -> str:
    candidates = _sensitive_info_candidates(evidence)
    if not candidates:
        return "当前证据未显示敏感信息类变量、参数或资产；不应扩大为敏感信息泄露影响。"
    labels = _candidate_labels(candidates)
    label_text = "、".join(labels[:8])
    if not any(explicit for _label, explicit in candidates):
        return (
            f"当前仅发现敏感信息候选词 {label_text}，但尚未证明其真实语义。"
            "需要结合报告位置、变量用途、上下游调用和输出/存储路径判断其是否为密钥、凭证、token、密码或其他敏感信息。"
            + " "
            + _sensitive_context_note(evidence)
        )
    return (
        f"当前发现敏感信息相关候选词 {label_text}。仍需用源码上下文和调用/数据流证据证明这些值会被未授权读取、写出、记录或返回，"
        "才能将影响归因为敏感信息泄露。"
        + " "
        + _sensitive_context_note(evidence)
    )


def _has_source_context(evidence: Sequence[CodeEvidence]) -> bool:
    return any(item.kind in SOURCE_CONTEXT_KINDS and (item.snippet or item.locations or item.data) for item in evidence)


def _context_locations(evidence: Sequence[CodeEvidence]) -> List[str]:
    locations = []
    seen = set()
    for item in evidence:
        if item.kind not in SOURCE_CONTEXT_KINDS:
            continue
        for location in item.locations:
            display = location.display()
            if display in seen:
                continue
            seen.add(display)
            locations.append(display)
    return locations


def _context_symbols(evidence: Sequence[CodeEvidence]) -> List[str]:
    symbols: List[str] = []
    for item in evidence:
        if item.kind not in SOURCE_CONTEXT_KINDS:
            continue
        symbols.extend(str(value) for value in item.data.get("symbols", []) if value)
        symbols.extend(str(value) for value in item.data.get("source_terms", []) if value)
        symbols.extend(str(value) for value in item.data.get("sink_terms", []) if value)
        for location in item.locations:
            if location.symbol:
                symbols.append(location.symbol)
    return list(dict.fromkeys(symbols))


def _business_logic_operations(evidence: Sequence[CodeEvidence]) -> List[str]:
    text = _evidence_context_text(evidence, source_only=True)
    operations = []
    for markers, description in BUSINESS_LOGIC_PATTERNS:
        if any(marker.lower() in text for marker in markers):
            operations.append(description)
    return list(dict.fromkeys(operations))


def _sensitive_context_note(evidence: Sequence[CodeEvidence]) -> str:
    if not _sensitive_info_candidates(evidence):
        return ""
    if not _has_source_context(evidence):
        return "当前缺少报告附近源码上下文，不能仅凭报告字段或变量名判断敏感性。"
    if _has_crypto_context(evidence):
        return "代码上下文出现加解密、签名、验签或摘要计算候选语义，应继续确认该变量是否实际参与这些操作。"
    return "代码上下文未见加解密、签名、凭证校验或密钥派生等操作，这会削弱仅凭 key 等命名认定为密钥的结论。"


def _has_crypto_context(evidence: Sequence[CodeEvidence]) -> bool:
    text = _evidence_context_text(evidence, source_only=True)
    return any(marker.lower() in text for marker in CRYPTO_CONTEXT_MARKERS)


def _sensitive_info_candidates(evidence: Sequence[CodeEvidence]) -> List[Tuple[str, bool]]:
    text = _sensitive_info_text(evidence)
    candidates: Dict[str, bool] = {}
    for term, label, explicit in SENSITIVE_INFO_TERMS:
        if _contains_sensitive_term(text, term):
            candidates[label] = candidates.get(label, False) or explicit
    return list(candidates.items())


def _candidate_labels(candidates: Sequence[Tuple[str, bool]]) -> List[str]:
    return list(dict.fromkeys(label for label, _explicit in candidates))


def _has_explicit_sensitive_info_evidence(evidence: Sequence[CodeEvidence]) -> bool:
    return any(explicit for _label, explicit in _sensitive_info_candidates(evidence))


def _is_sensitive_info_challenge(text: str) -> bool:
    normalized = re.sub(r"\s+", "", str(text or "").lower())
    if not normalized:
        return False
    markers = (
        "敏感信息",
        "敏感性",
        "密钥",
        "秘钥",
        "凭证",
        "密码",
        "口令",
        "令牌",
        "普通标识",
        "是否敏感",
        "secret",
        "credential",
        "password",
        "passwd",
        "token",
        "apikey",
        "api_key",
        "accesskey",
        "access_key",
        "privatekey",
        "private_key",
    )
    if any(marker in normalized for marker in markers):
        return True
    return bool(re.search(r"(?<![a-z0-9_])key(?![a-z0-9_])", normalized))


def _sensitive_info_text(evidence: Sequence[CodeEvidence]) -> str:
    return _evidence_context_text(evidence, source_only=False)


def _evidence_context_text(evidence: Sequence[CodeEvidence], source_only: bool) -> str:
    chunks: List[str] = []
    for item in evidence:
        if source_only and item.kind not in SOURCE_CONTEXT_KINDS:
            continue
        chunks.append(item.summary)
        chunks.append(item.source)
        if item.snippet:
            chunks.append(item.snippet[:2000])
        for location in item.locations[:10]:
            chunks.append(location.display())
            if location.symbol:
                chunks.append(location.symbol)
        chunks.extend(_string_fragments(item.data))
    return "\n".join(chunk for chunk in chunks if chunk).lower()[:60000]


def _string_fragments(value: Any, depth: int = 0) -> List[str]:
    if value is None or depth > 3:
        return []
    if isinstance(value, (str, int, float, bool)):
        return [str(value)[:1500]]
    if isinstance(value, dict):
        fragments: List[str] = []
        for key, item in list(value.items())[:40]:
            fragments.append(str(key)[:200])
            fragments.extend(_string_fragments(item, depth + 1))
        return fragments
    if isinstance(value, (list, tuple, set)):
        fragments = []
        for item in list(value)[:40]:
            fragments.extend(_string_fragments(item, depth + 1))
        return fragments
    return [str(value)[:500]]


def _contains_sensitive_term(text: str, term: str) -> bool:
    normalized_term = term.lower()
    if any(ord(char) > 127 for char in normalized_term) or " " in normalized_term:
        return normalized_term in text
    if normalized_term == "key":
        return bool(re.search(r"(?<![a-z0-9_])key(?![a-z0-9_])", text))
    return normalized_term in text


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

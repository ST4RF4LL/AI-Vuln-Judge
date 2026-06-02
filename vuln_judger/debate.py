from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence

from .evidence import EvidenceBundle
from .llm import LLMClient
from .models import (
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
    ):
        self.max_rounds = max_rounds
        self.affirmative_client = affirmative_client or llm_client
        self.negative_client = negative_client or llm_client

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
            "Argue that the SARIF finding is a real vulnerability candidate. Cite only provided evidence IDs.",
            bundle,
            extra="",
        ) or "The finding is grounded in source evidence and should be evaluated as a real vulnerability candidate."
        negative_claim = self._llm_claim(
            "NEGATIVE",
            "Challenge the vulnerability claim. Focus on hallucination, reachability, protection, and impact exaggeration. Cite only provided evidence IDs.",
            bundle,
            extra="\n".join(challenges),
        ) or (
            "The evidence must prove real code presence, reachability, missing effective protection, and non-exaggerated impact. "
            + (" ".join(challenges) if challenges else "No major counter-evidence was found.")
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
                "Respond to the negative challenges. Concede uncertainty where evidence is missing. Cite only provided evidence IDs.",
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
                claim=f"Final decision: {decision.verdict.value} with confidence {decision.confidence:.2f}. {decision.reasoning_summary}",
                evidence_ids=[item.evidence_id for item in evidence],
                resolved=decision.verdict != Verdict.INCONCLUSIVE,
            )
        )
        return turns

    def _challenges(self, bundle: EvidenceBundle) -> List[str]:
        evidence = bundle.evidence
        challenges: List[str] = []
        if _all_primary_locations_invalid(evidence):
            challenges.append("The reported location cannot be resolved in the provided source tree.")
        if not _has_meaningful_flow(evidence):
            challenges.append("No verified source-to-sink data flow or call path has been established.")
        if _has_protection(evidence):
            challenges.append("Nearby code contains possible validation, authorization, or sanitization logic that may mitigate the issue.")
        if _has_cpp_compile_gap(evidence):
            challenges.append("C++ evidence is degraded because no compile database was found.")
        if not _has_impact(evidence):
            challenges.append("The practical impact is not tied to assets, privileges, or reachable sinks.")
        challenges.extend(bundle.diagnostics)
        return challenges

    def _llm_claim(self, role: str, task: str, bundle: EvidenceBundle, extra: str) -> Optional[str]:
        client = self.affirmative_client if role == "AFFIRMATIVE" else self.negative_client
        if client is None:
            return None
        evidence_lines = []
        for item in bundle.evidence[:20]:
            evidence_lines.append(
                f"- {item.evidence_id} | {item.kind.value} | {item.strength.value} | {item.summary}"
            )
        system = (
            f"You are the {role} agent in a static vulnerability adjudication debate. "
            "You must not invent files, data flows, protections, or impacts. "
            "Every concrete claim must cite one or more evidence IDs from the prompt."
        )
        user = (
            f"Task: {task}\n"
            f"Finding: {bundle.finding.rule_id} - {bundle.finding.message}\n"
            f"Evidence:\n" + "\n".join(evidence_lines) + "\n"
            f"Additional context/challenges:\n{extra}\n"
            "Write one concise debate turn, no markdown table."
        )
        return client.complete(system, user)

    def _affirmative_reply(self, bundle: EvidenceBundle, challenges: Sequence[str]) -> str:
        evidence = bundle.evidence
        replies = []
        if _has_valid_location(evidence):
            replies.append("The SARIF location resolves to real source code.")
        if _has_meaningful_flow(evidence):
            replies.append("A SARIF or analyzer path provides reachability/data-flow evidence.")
        else:
            replies.append("Reachability remains insufficiently proven.")
        if _has_protection(evidence):
            replies.append("Protection evidence is present and must be reviewed for effectiveness rather than assumed effective.")
        if _has_impact(evidence):
            replies.append("Impact is mapped from the rule/message and any matching project context.")
        return " ".join(replies)

    def _decide(self, bundle: EvidenceBundle) -> DebateDecision:
        evidence = bundle.evidence
        challenges = self._challenges(bundle)
        if _all_primary_locations_invalid(evidence):
            return DebateDecision(
                verdict=Verdict.FALSE_POSITIVE,
                confidence=0.9,
                disputed_points=challenges,
                reasoning_summary="The SARIF finding does not resolve to a real source location in the provided project.",
                recommended_next_steps=["Verify that the SARIF report was generated from the same source revision."],
            )
        if _has_cpp_compile_gap(evidence) and not _has_meaningful_flow(evidence):
            return DebateDecision(
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.45,
                disputed_points=challenges,
                reasoning_summary="The C++ finding has real source evidence but lacks compile-database-backed data-flow or call-chain confirmation.",
                recommended_next_steps=["Provide compile_commands.json or a CodeQL database and rerun the judgement."],
            )
        if _has_meaningful_flow(evidence) and not _has_protection(evidence):
            return DebateDecision(
                verdict=Verdict.TRUE_POSITIVE,
                confidence=0.82 if _has_project_context(evidence) else 0.76,
                disputed_points=challenges,
                reasoning_summary="The finding resolves to real code and has verified path/data-flow evidence without identified mitigating protection.",
                recommended_next_steps=["Manually validate exploit preconditions and prioritize remediation based on asset impact."],
            )
        if _has_meaningful_flow(evidence) and _has_protection(evidence):
            return DebateDecision(
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.58,
                disputed_points=challenges,
                reasoning_summary="The vulnerable path appears real, but nearby protection logic needs human review for effectiveness.",
                recommended_next_steps=["Review the cited protection code and test whether attacker-controlled input can bypass it."],
            )
        if _has_weak_source_sink(evidence) and not _has_protection(evidence):
            return DebateDecision(
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.52,
                disputed_points=challenges,
                reasoning_summary="The code location exists and has source/sink-like terms, but source-to-sink reachability is not proven.",
                recommended_next_steps=["Run Atlas/CodeQL with indexing enabled or add SARIF code-flow paths from the scanner."],
            )
        if _has_protection(evidence):
            return DebateDecision(
                verdict=Verdict.FALSE_POSITIVE,
                confidence=0.62,
                disputed_points=challenges,
                reasoning_summary="The finding exists in source but lacks verified vulnerable flow and has nearby mitigation indicators.",
                recommended_next_steps=["Confirm the protection is effective before suppressing the SARIF finding."],
            )
        return DebateDecision(
            verdict=Verdict.INCONCLUSIVE,
            confidence=0.4,
            disputed_points=challenges,
            reasoning_summary="The source location exists, but the current evidence does not prove reachability, data flow, or mitigation status.",
            recommended_next_steps=["Collect stronger analyzer evidence or enrich the SARIF report with code flows."],
        )


def _ids(evidence: Iterable[CodeEvidence], *kinds: EvidenceKind) -> List[str]:
    accepted = set(kinds)
    return [item.evidence_id for item in evidence if item.kind in accepted]


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
        and "No compile_commands.json" in item.summary
        for item in evidence
    )


def _material_unresolved(challenges: Sequence[str]) -> bool:
    material = ("cannot be resolved", "No verified", "degraded", "outside configured")
    return any(any(marker in challenge for marker in material) for challenge in challenges)


def _protection_assessment(evidence: Sequence[CodeEvidence]) -> str:
    protections = [item for item in evidence if item.kind == EvidenceKind.PROTECTION]
    if not protections:
        return "No nearby validation, authorization, sanitization, or rate-limit evidence was identified."
    terms = []
    for item in protections:
        terms.extend(item.data.get("terms", []))
    unique_terms = sorted(set(terms))
    if unique_terms:
        return "Possible mitigating controls were found near the path: " + ", ".join(unique_terms)
    return "Possible mitigating controls were found, but their effectiveness is not established."


def _impact_assessment(evidence: Sequence[CodeEvidence]) -> str:
    impacts = []
    for item in evidence:
        if item.kind == EvidenceKind.IMPACT:
            impacts.extend(item.data.get("impacts", []))
        if item.kind == EvidenceKind.PROJECT_CONTEXT:
            impacts.append(f"Relevant project context: {item.summary}")
    if not impacts:
        return "No impact evidence was collected."
    return "; ".join(dict.fromkeys(impacts))

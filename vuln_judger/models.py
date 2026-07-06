from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class Verdict(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


class EvidenceKind(str, Enum):
    REPORT = "REPORT"
    SOURCE_ROOT = "SOURCE_ROOT"
    SOURCE_LOCATION = "SOURCE_LOCATION"
    SARIF_CODE_FLOW = "SARIF_CODE_FLOW"
    CALL_CHAIN = "CALL_CHAIN"
    DATA_FLOW = "DATA_FLOW"
    PROTECTION = "PROTECTION"
    IMPACT = "IMPACT"
    TOOL_DIAGNOSTIC = "TOOL_DIAGNOSTIC"
    PROJECT_CONTEXT = "PROJECT_CONTEXT"


class EvidenceStrength(str, Enum):
    STRONG = "STRONG"
    MEDIUM = "MEDIUM"
    WEAK = "WEAK"
    PARTIAL = "PARTIAL"


class DebateRole(str, Enum):
    AFFIRMATIVE = "AFFIRMATIVE"
    NEGATIVE = "NEGATIVE"
    MODERATOR = "MODERATOR"


@dataclass(frozen=True)
class SourceLocation:
    file: str
    line: Optional[int] = None
    column: Optional[int] = None
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    symbol: Optional[str] = None

    def display(self) -> str:
        if self.line is None:
            return self.file
        if self.column is None:
            return f"{self.file}:{self.line}"
        return f"{self.file}:{self.line}:{self.column}"


@dataclass
class Finding:
    finding_id: str
    rule_id: str
    message: str
    level: str
    locations: List[SourceLocation]
    code_flows: List[List[SourceLocation]] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def primary_location(self) -> Optional[SourceLocation]:
        return self.locations[0] if self.locations else None


@dataclass
class CodeEvidence:
    evidence_id: str
    kind: EvidenceKind
    strength: EvidenceStrength
    summary: str
    source: str
    locations: List[SourceLocation] = field(default_factory=list)
    snippet: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProjectFact:
    fact_id: str
    source: str
    title: str
    content: str
    tags: List[str] = field(default_factory=list)


@dataclass
class ProjectContext:
    root: Optional[str]
    facts: List[ProjectFact] = field(default_factory=list)

    def matching_facts(self, terms: Iterable[str], limit: int = 8) -> List[ProjectFact]:
        normalized_terms = [term.lower() for term in terms if term]
        scored: List[tuple[int, ProjectFact]] = []
        for fact in self.facts:
            text = f"{fact.title}\n{fact.content}\n{' '.join(fact.tags)}".lower()
            score = sum(1 for term in normalized_terms if term in text)
            if score:
                scored.append((score, fact))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [fact for _, fact in scored[:limit]]


@dataclass
class AgentConfig:
    name: str
    instructions: str = ""
    role: Optional[str] = None
    profile_id: Optional[str] = None
    path: Optional[str] = None
    starred: bool = False
    deletable: bool = True
    is_default: bool = False


@dataclass
class DebateTurn:
    role: DebateRole
    round_index: int
    claim: str
    evidence_ids: List[str] = field(default_factory=list)
    resolved: bool = False
    structured: Dict[str, Any] = field(default_factory=dict)
    raw_claim: Optional[str] = None


@dataclass
class VerificationCase:
    vulnerability_type: str = ""
    reported_message: str = ""
    reported_location: str = ""
    reported_source: str = ""
    reported_sink: str = ""
    dangerous_function: str = ""
    expected_attack_path: str = ""
    required_proof: List[str] = field(default_factory=list)


@dataclass
class EvidenceLedgerItem:
    id: str
    type: str
    claim: str
    status: str
    source: str
    location: str = ""
    confidence: float = 0.0
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class VerificationScorecard:
    source_location: str = "missing"
    entry_reachability: str = "missing"
    call_chain: str = "missing"
    data_flow: str = "missing"
    controllability: str = "missing"
    protection: str = "none"
    impact: str = "missing"
    verdict_label: str = ""
    confidence: float = 0.0
    rationale: List[str] = field(default_factory=list)


@dataclass
class VerdictReport:
    finding_id: str
    rule_id: str
    verdict: Verdict
    confidence: float
    reasoning_summary: str
    final_conclusion: str
    evidence_chain: List[CodeEvidence]
    debate: List[DebateTurn]
    disputed_points: List[str]
    protection_assessment: str
    impact_assessment: str
    source_locations: List[SourceLocation]
    recommended_next_steps: List[str]
    evidence_graph: Dict[str, Any] = field(default_factory=dict)
    verification_case: Dict[str, Any] = field(default_factory=dict)
    evidence_ledger: List[Dict[str, Any]] = field(default_factory=list)
    scorecard: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RunConfig:
    sarif_path: Path
    source_path: Path
    engine: str = "builtin"
    skills_path: Optional[Path] = None
    providers_file: Optional[Path] = None
    mcp_servers_file: Optional[Path] = None
    run_id: Optional[str] = None
    languages: List[str] = field(default_factory=list)
    max_rounds: int = 4
    auto_index_tools: bool = False
    enable_external_tools: bool = True
    enable_llm: bool = False
    llm_model: Optional[str] = None
    llm_endpoint: Optional[str] = None
    affirmative_provider_id: Optional[str] = None
    negative_provider_id: Optional[str] = None
    moderator_provider_id: Optional[str] = None
    affirmative_agent: Optional[AgentConfig] = None
    negative_agent: Optional[AgentConfig] = None
    moderator_agent: Optional[AgentConfig] = None
    created_at: Optional[str] = None
    resume_from_finding_index: int = 0
    resume_reports: List[Any] = field(default_factory=list)
    resume_diagnostics: List[str] = field(default_factory=list)


@dataclass
class RunReport:
    run_id: str
    created_at: str
    source_path: str
    sarif_path: str
    languages: List[str]
    finding_count: int
    project_context_facts: int
    reports: List[VerdictReport]
    status: str = "completed"
    llm_providers: Dict[str, Any] = field(default_factory=dict)
    agent_configs: Dict[str, Any] = field(default_factory=dict)
    diagnostics: List[str] = field(default_factory=list)
    completed_finding_count: int = 0
    current_finding_id: Optional[str] = None
    current_finding_index: Optional[int] = None
    resume_from_finding_id: Optional[str] = None
    resume_from_finding_index: Optional[int] = None


def to_jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "__dataclass_fields__"):
        return {key: to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    return str(value)

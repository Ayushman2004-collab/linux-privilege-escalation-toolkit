from dataclasses import asdict, dataclass, field
from typing import List, Dict, Any


@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: str
    confidence: str
    score: int
    summary: str
    evidence: List[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanContext:
    fast: bool = False
    roots: List[str] = field(default_factory=lambda: ["/"])
    max_findings: int = 500
    command_timeout: int = 10
    include_low: bool = True

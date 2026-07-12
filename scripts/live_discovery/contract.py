from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

CONTRACT_VERSION = "openstack-rehome-live-discovery/v1alpha1"


@dataclass
class CheckResult:
    check_id: str
    status: str
    reason: str
    resource_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ResourceNode:
    kind: str
    id: str
    side: str
    facts: Dict[str, Any] = field(default_factory=dict)
    evidence_ids: List[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.id}"

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["key"] = self.key
        return payload


@dataclass
class DependencyEdge:
    source: str
    target: str
    relation: str
    required: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CollectorResult:
    service: str
    side: str
    nodes: List[ResourceNode] = field(default_factory=list)
    edges: List[DependencyEdge] = field(default_factory=list)
    checks: List[CheckResult] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": CONTRACT_VERSION,
            "service": self.service,
            "side": self.side,
            "nodes": [item.to_dict() for item in self.nodes],
            "edges": [item.to_dict() for item in self.edges],
            "checks": [item.to_dict() for item in self.checks],
            "unknowns": list(self.unknowns),
            "blockers": list(self.blockers),
            "evidence": list(self.evidence),
        }

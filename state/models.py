from enum import Enum
from uuid import UUID, uuid4
from pydantic import BaseModel, Field
from typing import List, Dict, Any

class SeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class StatusEnum(str, Enum):
    PENDING = "PENDING"
    MITIGATED = "MITIGATED"
    ESCALATED = "ESCALATED"

class IncidentState(BaseModel):
    incident_id: UUID = Field(default_factory=uuid4)
    raw_logs: List[str] = Field(default_factory=list)
    detected_anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    associated_cves: List[str] = Field(default_factory=list)
    severity_score: SeverityEnum = SeverityEnum.LOW
    mitigation_plan: List[str] = Field(default_factory=list)
    execution_status: StatusEnum = StatusEnum.PENDING

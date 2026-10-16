from pydantic import BaseModel
from typing import List, Optional

class RiskAssessmentRequest(BaseModel):
    url: str
    request_types: List[str]
    business_justification: str
    existing_controls: List[str]

class RiskAssessmentResponse(BaseModel):
    url: str
    inherent_risk_score: int
    inherent_risk_classification: str
    residual_risk_score: int
    residual_risk_classification: str
    applied_controls: List[dict]
    recommendations: dict
    threat_analysis: List[str]
    suggested_mitigation_controls: List[str]
    final_recommendation: str

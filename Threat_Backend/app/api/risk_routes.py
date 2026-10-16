from fastapi import APIRouter
from app.models.risk_models import RiskAssessmentRequest, RiskAssessmentResponse
from app.services.risk_assessment import assess_risk

router = APIRouter()

@router.post("/assess-risk", response_model=RiskAssessmentResponse)
def assess_risk_route(request: RiskAssessmentRequest):
    return assess_risk(request)

from app.models.risk_models import RiskAssessmentRequest, RiskAssessmentResponse
from app.core.exception_risk_engine import calculate_inherent_risk
from app.core.control_mapping import apply_controls
from app.core.residual_risk_engine import classify_risk
from app.services.recommendation_engine import generate_recommendations
from app.services.scanner import scan_url_service

def assess_risk(req: RiskAssessmentRequest) -> RiskAssessmentResponse:
    # Get base URL threat data
    url_scan_result = scan_url_service(req.url)
    
    inherent_risk = calculate_inherent_risk(req.request_types, url_scan_result)
    
    residual_risk, applied_controls = apply_controls(inherent_risk, req.existing_controls)
    
    recs = generate_recommendations(req.request_types, residual_risk)
    
    return RiskAssessmentResponse(
        url=req.url,
        inherent_risk_score=inherent_risk,
        inherent_risk_classification=classify_risk(inherent_risk),
        residual_risk_score=residual_risk,
        residual_risk_classification=classify_risk(residual_risk),
        applied_controls=applied_controls,
        recommendations={}, # Just backwards compat
        threat_analysis=recs["threat_analysis"],
        suggested_mitigation_controls=recs["suggested_mitigation_controls"],
        final_recommendation=recs["final_recommendation"]
    )

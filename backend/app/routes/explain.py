"""AI explanation route."""
from fastapi import APIRouter

from app.models import ExplainRequest, ExplainResponse
from app.services.explainer import explain_finding

router = APIRouter(prefix="/api/v1", tags=["explain"])


@router.post("/explain", response_model=ExplainResponse)
async def explain_security_finding(request: ExplainRequest):
    """Explain a single deterministic scanner finding."""
    return await explain_finding(request.finding)

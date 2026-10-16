"""
Email Assessment API routes.

POST /api/v1/validate-domain   – single domain validation
POST /api/v1/validate-batch    – concurrent multi-domain validation
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.dns_validator import validate_domain

router = APIRouter()

# ─────────────────────────────────────────────────────────────────────────────
# PYDANTIC MODELS
# ─────────────────────────────────────────────────────────────────────────────

class DomainValidationRequest(BaseModel):
    domain: str = Field(..., example="example.com", description="Domain to validate (no URL scheme needed)")
    selectors: Optional[List[str]] = Field(
        default=None,
        example=["k1", "pps1"],
        description="Custom DKIM selectors to probe (comma-separated on the UI side)",
    )
    raw_header: Optional[str] = Field(
        default=None,
        description="Raw email header text; d= and s= tags are auto-extracted",
    )
    resolver: Optional[str] = Field(
        default="default",
        description="DNS resolver to use: 'default' (1.1.1.1), 'google' (8.8.8.8), 'quad9' (9.9.9.9)",
    )


class BatchValidationRequest(BaseModel):
    domains: List[str] = Field(..., description="List of domains to validate concurrently")
    selectors: Optional[List[str]] = Field(default=None)
    resolver: Optional[str] = Field(default="default")


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/validate-domain", summary="Validate a single domain's email security posture")
def validate_single_domain(req: DomainValidationRequest) -> dict:
    """
    Check SPF, DMARC, and DKIM for one domain.
    Optionally parse a raw email header to extract selectors automatically.
    Returns the full evaluation payload with **meets_qualification**.
    """
    return validate_domain(
        domain=req.domain,
        selectors=req.selectors,
        raw_header=req.raw_header,
        resolver_name=req.resolver or "default",
    )


@router.post("/validate-batch", summary="Validate multiple domains concurrently")
async def validate_batch_domains(req: BatchValidationRequest) -> dict:
    """
    Validate a list of domains concurrently using a thread-pool executor
    (DNS resolution is blocking; asyncio.gather keeps the event loop free).
    """
    loop = asyncio.get_event_loop()

    with ThreadPoolExecutor(max_workers=min(len(req.domains), 10)) as pool:
        futures = [
            loop.run_in_executor(
                pool,
                lambda d=domain: validate_domain(
                    domain=d,
                    selectors=req.selectors,
                    resolver_name=req.resolver or "default",
                ),
            )
            for domain in req.domains
        ]
        results = await asyncio.gather(*futures)

    qualified   = [r for r in results if r.get("meets_qualification")]
    unqualified = [r for r in results if not r.get("meets_qualification")]

    return {
        "total":              len(results),
        "qualified_count":    len(qualified),
        "unqualified_count":  len(unqualified),
        "results":            results,
    }

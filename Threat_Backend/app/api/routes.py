from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List
from app.services.scanner import scan_url_service, scan_urls_batch
from app.services.ssl_labs_service import check_ssl_labs
from app.services.mx_tools_service import check_mx_tools
from app.services.pdf_report import generate_pdf_report
import io

router = APIRouter()


class BatchScanRequest(BaseModel):
    urls: List[str]

class ReportRequest(BaseModel):
    urls: List[str]
    final_comment: str = ""
    app_name: str | None = None
    can_id: str | None = None
    server_ip: str | None = None
    request_id: str | None = None


@router.post("/scan-url")
def scan_url(url: str = Query(..., description="The URL to scan for threats")):
    return scan_url_service(url)


@router.post("/scan-batch")
def scan_batch(request: BatchScanRequest):
    """Scan multiple URLs and return all results."""
    results = scan_urls_batch(request.urls)
    return {"results": results, "total": len(results)}


@router.get("/ssl-check")
def ssl_check(url: str = Query(..., description="Domain or URL to check SSL")):
    """Standalone SSL Labs check for a single domain."""
    return check_ssl_labs(url)


@router.get("/mx-check")
def mx_check(url: str = Query(..., description="Domain or URL to check MX records")):
    """Standalone MX / DNS analysis for a single domain."""
    return check_mx_tools(url)


@router.post("/report/pdf")
def download_pdf_report(request: ReportRequest):
    """
    Generate a PDF report for one or more URLs.
    Accepts the same batch request body; scans (or fetches from cache)
    each URL, then builds a downloadable PDF.
    """
    results = scan_urls_batch(request.urls)
    pdf_bytes = generate_pdf_report(
        results, 
        request.final_comment,
        request.app_name,
        request.can_id,
        request.server_ip,
        request.request_id
    )

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=threat_intel_report.pdf"
        },
    )

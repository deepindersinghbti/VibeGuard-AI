"""Scan route."""
from fastapi import APIRouter, UploadFile, File, HTTPException, status
from app.services.zip_handler import extract_zip_temp, ZipExtractionError
from app.services.scanner import generate_summary, scan_directory
from app.models import ScanResponse

router = APIRouter(prefix="/api/v1", tags=["scan"])


@router.post("/scan/zip", response_model=ScanResponse)
async def upload_and_scan_zip(file: UploadFile = File(...)):
    """
    Upload and scan a ZIP file for security issues.
    
    Returns a list of Finding objects sorted by severity (critical → low),
    then by file path and line number.
    """
    # Validate file is ZIP
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a .zip file"
        )
    
    # Read file content
    content = await file.read()
    
    # Check file size (25MB limit)
    if len(content) > 25 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File exceeds 25MB limit"
        )
    
    try:
        # Extract ZIP safely and automatically clean up with context manager
        with extract_zip_temp(content) as extract_dir:
            # Scan the extracted directory
            findings = scan_directory(extract_dir)
            return ScanResponse(summary=generate_summary(findings), findings=findings)
        
    except ZipExtractionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during scanning"
        )

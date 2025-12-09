import json
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request
import uvicorn
from pydantic import ValidationError

from models.schemas import AnalysisRequest, AnalysisResponse
from utils.logger import get_logger
from workflows.evidence_analysis import EvidenceAnalysisWorkflow

app = FastAPI(title="Evidence Analysis Microservice", version="1.0.0")
logger = get_logger(__name__)

# Initialize workflow
workflow = EvidenceAnalysisWorkflow()


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_evidence(
    request: Request,
    background_tasks: BackgroundTasks,
    complaint_id_query: Optional[str] = Query(default=None, alias="complaint_id")
):
    """
    Main endpoint to trigger evidence analysis for ALL files in a complaint
    """
    try:
        header_complaint_id = (
            request.headers.get("x-complaint-id")
            or request.headers.get("complaint-id")
        )

        body_complaint_id: Optional[str] = None
        try:
            payload = await request.json()
            if not isinstance(payload, dict):
                raise HTTPException(
                    status_code=400,
                    detail="Request body must be a JSON object containing complaint_id",
                )
            body_model = AnalysisRequest(**payload)
            body_complaint_id = body_model.complaint_id
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Malformed JSON payload: {exc.msg}",
            ) from exc
        except ValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail=json.loads(exc.json()),
            ) from exc

        if body_complaint_id and complaint_id_query and body_complaint_id != complaint_id_query:
            raise HTTPException(
                status_code=400,
                detail="complaint_id mismatch between body and query",
            )

        if body_complaint_id and header_complaint_id and body_complaint_id != header_complaint_id:
            raise HTTPException(
                status_code=400,
                detail="complaint_id mismatch between headers and body",
            )

        if complaint_id_query and header_complaint_id and complaint_id_query != header_complaint_id:
            raise HTTPException(
                status_code=400,
                detail="complaint_id mismatch between headers and query",
            )

        complaint_id = complaint_id_query or body_complaint_id or header_complaint_id

        if not complaint_id:
            raise HTTPException(
                status_code=422,
                detail="complaint_id is required via query param, header, or body",
            )

        # Fetch evidence identifiers from database using complaint_id
        evidence_ids = await workflow.db_manager.get_evidence_ids(complaint_id)

        if not evidence_ids:
            raise HTTPException(
                status_code=404, 
                detail=f"Evidence not found for complaint_id: {complaint_id}"
            )

        # Add processing task to background - processes ALL evidence files
        background_tasks.add_task(
            workflow.process_evidences, 
            complaint_id
        )
        
        return AnalysisResponse(
            status="processing",
            message=f"Evidence analysis started for {len(evidence_ids)} file(s)",
            complaint_id=complaint_id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/status/{complaint_id}")
async def get_analysis_status(complaint_id: str):
    """
    Check the status of evidence analysis
    """
    try:
        status = await workflow.db_manager.complaints.get_analysis_status(complaint_id)
        
        if not status:
            raise HTTPException(
                status_code=404,
                detail=f"No analysis found for complaint_id: {complaint_id}"
            )
        
        return status
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """
    Health check endpoint
    """
    return {"status": "healthy", "service": "evidence-analysis"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
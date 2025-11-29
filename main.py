from fastapi import FastAPI, HTTPException, BackgroundTasks
import uvicorn

from models.schemas import AnalysisRequest, AnalysisResponse
from workflows.evidence_analysis import EvidenceAnalysisWorkflow

app = FastAPI(title="Evidence Analysis Microservice", version="1.0.0")

# Initialize workflow
workflow = EvidenceAnalysisWorkflow()


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_evidence(
    request: AnalysisRequest, 
    background_tasks: BackgroundTasks
):
    """
    Main endpoint to trigger evidence analysis for ALL files in a complaint
    """
    try:
        # Fetch evidence identifiers from database using complaint_id
        evidence_ids = await workflow.db_manager.get_evidence_ids(request.complaint_id)

        if not evidence_ids:
            raise HTTPException(
                status_code=404, 
                detail=f"Evidence not found for complaint_id: {request.complaint_id}"
            )

        # Add processing task to background - processes ALL evidence files
        background_tasks.add_task(
            workflow.process_evidences, 
            request.complaint_id
        )
        
        return AnalysisResponse(
            status="processing",
            message=f"Evidence analysis started for {len(evidence_ids)} file(s)",
            complaint_id=request.complaint_id
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
from pydantic import BaseModel


class AnalysisRequest(BaseModel):
    complaint_id: str


class AnalysisResponse(BaseModel):
    status: str
    message: str
    complaint_id: str

from datetime import datetime
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo.errors import PyMongoError

from utils.logger import get_logger

logger = get_logger(__name__)


class ComplaintsMasterTableRepository:
    """Data access layer for the complaints master collection."""

    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    async def get_evidence_ids(self, complaint_id: str) -> List[str]:
        """Return all evidence identifiers for the given complaint."""
        try:
            document = await self.collection.find_one(
                {"complaint_id": complaint_id},
                {"_id": 0, "evidences.evidence_id": 1},
            )

            if not document:
                logger.warning("Complaint not found while listing evidences: %s", complaint_id)
                return []

            evidences = document.get("evidences", [])
            evidence_ids = [evidence.get("evidence_id") for evidence in evidences if evidence.get("evidence_id")]

            if not evidence_ids:
                logger.info("No evidences recorded for complaint_id: %s", complaint_id)

            return evidence_ids

        except PyMongoError as exc:
            logger.error("Error retrieving evidence ids: %s", exc)
            raise

    async def get_analysis_status(self, complaint_id: str) -> Optional[Dict[str, Any]]:
        """Return current analysis status for a complaint."""
        try:
            document = await self.collection.find_one(
                {"complaint_id": complaint_id},
                {"complaint_id": 1, "overall_status": 1, "evidences": 1, "_id": 0},
            )

            if not document:
                return None

            evidences = document.get("evidences", [])
            return {
                "complaint_id": complaint_id,
                "overall_status": document.get("overall_status", "pending"),
                "total_evidences": len(evidences),
                "evidences_status": [
                    {
                        "evidence_id": evidence.get("evidence_id"),
                        "filename": evidence.get("filename"),
                        "status": evidence.get("file_scanner_report", {}).get("status", "pending"),
                        "last_updated": evidence.get("file_scanner_report", {}).get("last_updated"),
                    }
                    for evidence in evidences
                ],
            }

        except PyMongoError as exc:
            logger.error("Error getting analysis status: %s", exc)
            raise

    async def create_complaint_entry(
        self,
        complaint_id: str,
        minio_links: Optional[List[str]] = None,
    ) -> bool:
        """Create a new complaint entry in the database."""
        try:
            evidences: List[Dict[str, Any]] = []
            if minio_links:
                for idx, link in enumerate(minio_links):
                    evidences.append(
                        {
                            "evidence_id": f"EVD-{idx + 1:03d}",
                            "minio_link": link,
                            "filename": None,
                            "file_hashes": [],
                            "file_scanner_report": {
                                "status": "pending",
                                "last_updated": datetime.utcnow().isoformat(),
                                "entropy": None,
                            },
                        }
                    )

            document = {
                "complaint_id": complaint_id,
                "overall_status": "pending",
                "evidences": evidences,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
            }

            await self.collection.insert_one(document)
            logger.info(
                "Created complaint entry: %s with %d evidence(s)",
                complaint_id,
                len(evidences),
            )
            return True

        except PyMongoError as exc:
            logger.error("Error creating complaint entry: %s", exc)
            raise

    async def add_evidence_to_complaint(
        self,
        complaint_id: str,
        minio_link: str,
        evidence_id: Optional[str] = None,
    ) -> Optional[str]:
        """Add a new evidence file to an existing complaint."""
        try:
            document = await self.collection.find_one({"complaint_id": complaint_id})

            if not document:
                logger.error("Complaint not found: %s", complaint_id)
                return None

            current_count = len(document.get("evidences", []))
            evidence_identifier = evidence_id or f"EVD-{current_count + 1:03d}"

            new_evidence = {
                "evidence_id": evidence_identifier,
                "minio_link": minio_link,
                "filename": None,
                "file_hashes": [],
                "file_scanner_report": {
                    "status": "pending",
                    "last_updated": datetime.utcnow().isoformat(),
                    "entropy": None,
                },
            }

            await self.collection.update_one(
                {"complaint_id": complaint_id},
                {
                    "$push": {"evidences": new_evidence},
                    "$set": {"updated_at": datetime.utcnow()},
                },
            )

            logger.info(
                "Added evidence %s to complaint: %s", evidence_identifier, complaint_id
            )
            return evidence_identifier

        except PyMongoError as exc:
            logger.error("Error adding evidence to complaint: %s", exc)
            raise

    async def get_all_complaints(self, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Return complaints with pagination support."""
        try:
            cursor = self.collection.find({}).skip(skip).limit(limit)
            complaints = await cursor.to_list(length=limit)

            for complaint in complaints:
                if "_id" in complaint:
                    complaint["_id"] = str(complaint["_id"])

            return complaints

        except PyMongoError as exc:
            logger.error("Error fetching complaints: %s", exc)
            raise

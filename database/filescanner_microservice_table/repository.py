from datetime import datetime
from typing import Any, Dict

from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo.errors import PyMongoError

from utils.logger import get_logger

logger = get_logger(__name__)


class FilescannerMicroserviceTableRepository:
    """Data access layer for the filescanner microservice collection."""

    def __init__(self, collection: AsyncIOMotorCollection):
        self.collection = collection

    async def store_analysis_results(
        self,
        complaint_id: str,
        evidence_id: str,
        results: Dict[str, Any],
    ) -> bool:
        """Persist analysis output for a specific evidence file."""
        try:
            file_hash = results.get("hash") or results.get("file_hash")

            # Allow callers to set an explicit report structure; otherwise store
            # the remaining material from the results payload so nothing is lost.
            report_payload = results.get("report")

            if report_payload is None:
                excluded_keys = {
                    "complaint_id",
                    "evidence_id",
                    "hash",
                    "file_hash",
                }
                report_payload = {
                    key: value
                    for key, value in results.items()
                    if key not in excluded_keys
                }

            payload: Dict[str, Any] = {
                "file_hash": file_hash,
                "report": report_payload,
            }

            update_result = await self.update_evidence_report(
                complaint_id,
                evidence_id,
                payload,
            )

            if update_result:
                logger.info(
                    "Analysis results stored for complaint_id: %s, evidence_id: %s",
                    complaint_id,
                    evidence_id,
                )
                return True

            logger.warning(
                "No evidence found to update for complaint_id: %s, evidence_id: %s",
                complaint_id,
                evidence_id,
            )
            return False

        except PyMongoError as exc:
            logger.error("Error storing analysis results: %s", exc)
            raise

    async def ensure_evidence_entry(
        self,
        complaint_id: str,
        evidence_id: str,
        file_hash: str,
    ) -> bool:
        """Ensure an evidence placeholder exists for the given complaint."""
        try:
            placeholder_report: Dict[str, Any] = {}

            update_existing = await self.collection.update_one(
                {
                    "complaint_id": complaint_id,
                    "evidences.evidence_id": evidence_id,
                },
                {
                    "$set": {
                        "evidences.$.file_hash": file_hash,
                        "updated_at": datetime.utcnow(),
                    }
                },
            )

            if update_existing.matched_count > 0:
                if update_existing.modified_count == 0:
                    logger.info(
                        "Evidence %s for complaint %s already present in filescanner table",
                        evidence_id,
                        complaint_id,
                    )
                return True

            new_evidence = {
                "evidence_id": evidence_id,
                "file_hash": file_hash,
                "report": placeholder_report,
            }

            upsert_result = await self.collection.update_one(
                {"complaint_id": complaint_id},
                {
                    "$setOnInsert": {
                        "complaint_id": complaint_id,
                        "evidences": [],
                        "created_at": datetime.utcnow(),
                    },
                    "$set": {"updated_at": datetime.utcnow()},
                },
                upsert=True,
            )

            if upsert_result.upserted_id is not None:
                logger.info(
                    "Created filescanner record for complaint %s",
                    complaint_id,
                )

            push_result = await self.collection.update_one(
                {"complaint_id": complaint_id},
                {
                    "$push": {"evidences": new_evidence},
                    "$set": {"updated_at": datetime.utcnow()},
                },
            )

            if push_result.modified_count > 0:
                logger.info(
                    "Ensured evidence %s for complaint %s in filescanner table",
                    evidence_id,
                    complaint_id,
                )
                return True

            logger.warning(
                "Failed to ensure evidence %s for complaint %s",
                evidence_id,
                complaint_id,
            )
            return False

        except PyMongoError as exc:
            logger.error("Error ensuring evidence entry: %s", exc)
            raise

    async def add_file_hash(
        self,
        complaint_id: str,
        evidence_id: str,
        hash_value: str,
    ) -> bool:
        """Attach or update a file hash for a specific evidence entry."""
        try:
            update_result = await self.collection.update_one(
                {
                    "complaint_id": complaint_id,
                    "evidences.evidence_id": evidence_id,
                },
                {
                    "$set": {
                        "evidences.$.file_hash": hash_value,
                        "updated_at": datetime.utcnow(),
                    }
                },
            )

            if update_result.matched_count > 0:
                logger.info(
                    "Stored hash for complaint_id: %s, evidence_id: %s",
                    complaint_id,
                    evidence_id,
                )
                return True

            logger.warning(
                "No document found for complaint_id: %s while adding hash", complaint_id
            )
            return False

        except PyMongoError as exc:
            logger.error("Error adding file hash: %s", exc)
            raise

    async def update_evidence_report(
        self,
        complaint_id: str,
        evidence_id: str,
        report: Dict[str, Any],
    ) -> bool:
        """Update the simplified report information for an evidence entry."""
        try:
            update_operations: Dict[str, Any] = {}

            file_hash = report.get("file_hash")
            if file_hash:
                update_operations["evidences.$.file_hash"] = file_hash

            if "report" in report:
                update_operations["evidences.$.report"] = report.get("report")

            if not update_operations:
                logger.warning(
                    "No report fields provided for complaint_id: %s, evidence_id: %s",
                    complaint_id,
                    evidence_id,
                )
                return False

            update_operations["updated_at"] = datetime.utcnow()

            update_result = await self.collection.update_one(
                {
                    "complaint_id": complaint_id,
                    "evidences.evidence_id": evidence_id,
                },
                {"$set": update_operations},
            )

            if update_result.matched_count > 0:
                logger.info(
                    "Updated report for complaint_id: %s, evidence_id: %s",
                    complaint_id,
                    evidence_id,
                )
                return True

            logger.warning(
                "Failed to update evidence %s in complaint %s",
                evidence_id,
                complaint_id,
            )
            return False

        except PyMongoError as exc:
            logger.error("Error updating evidence report: %s", exc)
            raise

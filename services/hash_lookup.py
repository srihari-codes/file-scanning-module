from typing import Dict, Optional

from database.db_manager import DatabaseManager
from database.filescanner_microservice_table.repository import (
    FilescannerMicroserviceTableRepository,
)
from config.settings import settings
from utils.logger import get_logger
import aiohttp
from datetime import datetime

logger = get_logger(__name__)


class HashLookupService:
    def __init__(
        self,
        *,
        db_manager: Optional[DatabaseManager] = None,
        filescanner_repo: Optional[FilescannerMicroserviceTableRepository] = None,
    ) -> None:
        """Create a hash lookup helper.

        Args:
            db_manager: Optional shared DatabaseManager to avoid opening a new
                Motor client. If provided, ``filescanner_repo`` is derived from it
                unless explicitly supplied.
            filescanner_repo: Direct repository handle; allows callers that
                already resolved the collection to inject it directly.
        """

        if filescanner_repo is not None:
            self.filescanner_repo = filescanner_repo
            self.db_manager = db_manager
        elif db_manager is not None:
            self.db_manager = db_manager
            self.filescanner_repo = db_manager.filescanner
        else:
            self.db_manager = DatabaseManager()
            self.filescanner_repo = self.db_manager.filescanner

    async def lookup_hash(
        self,
        file_hash: str,
        complaint_id: str,
        evidence_id: str
    ) -> Dict[str, bool]:
        result = {
            "local_lookup": False,
            "online_lookup": False
        }

        try:
            preview = file_hash[:16] if file_hash else ""
            logger.info(f"Starting local hash lookup for hash: {preview}...")
            local_result = await self._local_hash_lookup(file_hash, complaint_id, evidence_id)

            if local_result:
                result["local_lookup"] = True
                logger.info(
                    f"Hash found locally. Copied report to complaint_id: {complaint_id}, "
                    f"evidence_id: {evidence_id}"
                )
                return result

            logger.info("Hash not found locally. Checking VirusTotal...")
            online_result = await self._online_hash_lookup(file_hash, complaint_id, evidence_id)

            if online_result:
                result["online_lookup"] = True
                logger.info(
                    f"Hash found on VirusTotal. Populated report for complaint_id: {complaint_id}, "
                    f"evidence_id: {evidence_id}"
                )
            else:
                logger.info("Hash not found on VirusTotal either")

            return result

        except Exception as e:
            logger.error(f"Error in master hash lookup: {e}")
            raise

    async def _local_hash_lookup(
        self,
        file_hash: str,
        new_complaint_id: str,
        new_evidence_id: str
    ) -> bool:
        try:
            query = {
                "evidences.file_hash": file_hash
            }

            document = await self.filescanner_repo.collection.find_one(query)

            if not document:
                logger.info("Hash not found in local database")
                return False

            existing_evidence = next(
                (
                    evidence
                    for evidence in document.get("evidences", [])
                    if evidence.get("file_hash") == file_hash
                ),
                None
            )

            if not existing_evidence:
                logger.warning("Hash found but no matching evidence details exist")
                return False

            existing_report = existing_evidence.get("report")

            if not existing_report:
                logger.warning("Hash found but no report exists")
                return False

            update_result = await self.filescanner_repo.update_evidence_report(
                new_complaint_id,
                new_evidence_id,
                {
                    "file_hash": file_hash,
                    "report": existing_report
                }
            )

            if update_result:
                logger.info(
                    f"Copied report from complaint_id: {document.get('complaint_id')} "
                    f"to complaint_id: {new_complaint_id}, evidence_id: {new_evidence_id}"
                )
                return True

            logger.warning(
                f"Failed to update evidence {new_evidence_id} in complaint {new_complaint_id}"
            )
            return False

        except Exception as e:
            logger.error(f"Error during local hash lookup: {e}")
            raise

    async def _online_hash_lookup(
        self,
        file_hash: str,
        complaint_id: str,
        evidence_id: str
    ) -> bool:
        try:
            if not settings.VIRUSTOTAL_API_KEY:
                logger.warning("VirusTotal API key not configured")
                return False

            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 404:
                        logger.info("Hash not found on VirusTotal")
                        return False

                    if response.status != 200:
                        logger.error(f"VirusTotal API error: {response.status}")
                        return False

                    vt_data = await response.json()

                    data = vt_data.get("data", {})
                    attributes = data.get("attributes", {})
                    last_analysis_stats = attributes.get("last_analysis_stats", {}) or {}
                    last_analysis_results = attributes.get("last_analysis_results", {}) or {}

                    total_scanners = sum(last_analysis_stats.values())
                    if total_scanners == 0:
                        total_scanners = len(last_analysis_results)

                    malicious = last_analysis_stats.get("malicious", 0)
                    suspicious = last_analysis_stats.get("suspicious", 0)
                    undetected = last_analysis_stats.get("undetected", 0)

                    risk_level = (
                        "high" if malicious > 5
                        else "medium" if malicious > 0 or suspicious > 0
                        else "low"
                    )

                    malicious_engines = [
                        f"{engine}: {details.get('result')}"
                        for engine, details in last_analysis_results.items()
                        if details.get("category") == "malicious" and details.get("result")
                    ]

                    completed_at = datetime.utcnow().isoformat() + "Z"

                    virustotal_report = {
                        "completed_at": completed_at,
                        "stats": {
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "undetected": undetected,
                            "total_scanners": total_scanners,
                        },
                        "risk_level": risk_level,
                        "meaningful_name": attributes.get("meaningful_name"),
                        "reputation": attributes.get("reputation"),
                    }

                    if malicious_engines:
                        virustotal_report["malicious_detections"] = malicious_engines

                    if last_analysis_results:
                        virustotal_report["analysis_results"] = last_analysis_results

                    # Preserve complete VirusTotal payload for downstream analysis
                    if data:
                        virustotal_report["raw_data"] = data

                    meta = vt_data.get("meta")
                    if meta:
                        virustotal_report["meta"] = meta

                    context_attributes = vt_data.get("context_attributes")
                    if context_attributes:
                        virustotal_report["context_attributes"] = context_attributes

                    links = vt_data.get("links")
                    if links:
                        virustotal_report["links"] = links

                    virustotal_report["raw_response"] = vt_data

                    detection_rate = f"{malicious}/{total_scanners}" if total_scanners else "0/0"

                    threat_label = attributes.get("popular_threat_classification", {}).get(
                        "suggested_threat_label"
                    )

                    summary_section = {
                        "source": "virustotal",
                        "message": "Hash found on VirusTotal.",
                        "detection_rate": detection_rate,
                        "risk_level": risk_level,
                    }

                    if threat_label:
                        summary_section["threat_label"] = threat_label

                    permalink = attributes.get("permalink") or data.get("links", {}).get("self")
                    if permalink:
                        summary_section["permalink"] = permalink

                    report_payload = {
                        "virustotal": virustotal_report,
                        "summary": summary_section,
                        "metadata": {
                            "generated_at": completed_at,
                            "source": "virustotal",
                        },
                    }

                    update_result = await self.filescanner_repo.update_evidence_report(
                        complaint_id,
                        evidence_id,
                        {
                            "file_hash": file_hash,
                            "report": report_payload
                        }
                    )

                    if update_result:
                        logger.info(
                            f"Populated report from VirusTotal for complaint_id: {complaint_id}, "
                            f"evidence_id: {evidence_id}. Detection rate: {detection_rate}"
                        )
                        return True

                    logger.warning(
                        f"Failed to update evidence {evidence_id} in complaint {complaint_id}"
                    )
                    return False

        except Exception as e:
            logger.error(f"Error during online hash lookup: {e}")
            return False
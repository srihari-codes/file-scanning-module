import asyncio
import json
from pathlib import Path
from typing import Dict, Any
import aiohttp
from services.file_data import FileDataService
from services.file_hashing import FileHashingService
from services.hash_lookup import HashLookupService
from services.mime_sniffing import MimeSniffingService
from services.file_entropy import FileEntropyService
from services.clam_av import ClamAVService
from services.yara_scan import YaraScanService
from services.report_generator import ReportGeneratorService
from utils.logger import get_logger
from processors.image_processor import ImageProcessor
from processors.video_processor import VideoProcessor
from processors.audio_processor import AudioProcessor
from processors.document_processor import DocumentProcessor
from processors.spreadsheet_processor import SpreadsheetProcessor
from processors.archive_processor import ArchiveProcessor
from processors.executable_processor import ExecutableProcessor
from processors.apk_processor import ApkProcessor
from database.db_manager import DatabaseManager

logger = get_logger(__name__)


class EvidenceAnalysisWorkflow:
    def __init__(self):
        # Initialize services
        self.db_manager = DatabaseManager()
        self.filescanner_repo = self.db_manager.filescanner
        self.file_data_service = FileDataService()
        self.file_hashing_service = FileHashingService()
        self.hash_lookup_service = HashLookupService()
        self.mime_sniffing_service = MimeSniffingService()
        self.clam_av_service = ClamAVService()
        self.yara_scan_service = YaraScanService()
        self.report_generator_service = ReportGeneratorService()
        self.file_entropy_service = FileEntropyService()
        
        # Initialize file type processors
        self.processors = {
            "image": ImageProcessor(),
            "video": VideoProcessor(),
            "audio": AudioProcessor(),
            "document": DocumentProcessor(),
            "spreadsheet": SpreadsheetProcessor(),
            "email": EmailProcessor(),
            "archive": ArchiveProcessor(),
            "webpage": WebpageProcessor(),
            "log": LogProcessor(),
            "executable": ExecutableProcessor(),
            "apk": ApkProcessor()
        }
    
    async def process_evidences(self, complaint_id: str) -> Dict[str, Any]:
        """Process every evidence file associated with ``complaint_id``."""
        overall_results = {
            "complaint_id": complaint_id,
            "overall_status": "processing",
            "evidences_processed": 0,
            "evidences_failed": 0,
            "evidence_results": []
        }

        try:
            evidence_entries = await self.db_manager.get_evidence_ids(complaint_id)

            if not evidence_entries:
                return {
                    "complaint_id": complaint_id,
                    "overall_status": "no_evidences",
                    "message": "No evidence files found for this complaint_id"
                }

            logger.info(f"Processing {len(evidence_entries)} evidence file(s) for complaint_id: {complaint_id}")

            for entry in evidence_entries:
                # Support both old structure (dict/ID) and new structure (URL string)
                if isinstance(entry, str):
                    # New DB format: entry is a URL pointing to the evidence
                    evidence_id = entry  # use the URL as identifier for storage/lookup
                    evidence_url = entry
                elif isinstance(entry, dict):
                    # Old format for backward compatibility
                    evidence_id = entry.get("evidence_id")
                    evidence_url = None
                else:
                    evidence_id = str(entry)
                    evidence_url = None

                evidence_result: Dict[str, Any] = {
                    "complaint_id": complaint_id,
                    "evidence_id": evidence_id,
                }
                try:
                    # Fetch file_name and file_data either from URL or via FileDataService
                    if evidence_url and evidence_url.lower().startswith(("http://", "https://")):
                        file_name = Path(evidence_url).name
                        async with aiohttp.ClientSession(timeout=self.file_data_service._timeout) as session:
                            async with session.get(evidence_url, headers=self.file_data_service._headers) as resp:
                                if resp.status == 404:
                                    logger.warning("Evidence file missing during download | url=%s", evidence_url)
                                    raise FileNotFoundError("Evidence file not found at provided URL")
                                if resp.status != 200:
                                    body = await resp.text()
                                    logger.error(
                                        "Evidence URL download failed | status=%s | url=%s | body=%s",
                                        resp.status,
                                        evidence_url,
                                        body,
                                    )
                                    raise RuntimeError("Failed to download evidence file from provided URL")
                                file_data = await resp.read()
                    else:
                        # Fallback to previous behavior (complaint_id + evidence_id)
                        file_name, file_data = await self.file_data_service.fetch_file_data(complaint_id, evidence_id)

                    evidence_result["file_name"] = file_name
                    file_name_extension = (
                        Path(file_name).suffix.lstrip(".").lower() if file_name else None
                    )
                    evidence_result["file_name_extension"] = file_name_extension
                    hash_result = await self.file_hashing_service.hash_file(file_data)
                    evidence_result["hash"] = hash_result

                    ensured = await self.filescanner_repo.ensure_evidence_entry(
                        complaint_id,
                        evidence_id,
                        hash_result,
                    )

                    if not ensured:
                        logger.warning(
                            "Unable to prepare filescanner entry for complaint %s, evidence %s",
                            complaint_id,
                            evidence_id,
                        )

                    lookup_result = await self.hash_lookup_service.lookup_hash(hash_result, complaint_id, evidence_id)
                    evidence_result["hash_lookup"] = json.dumps(lookup_result)

                    if lookup_result.get("local_lookup") or lookup_result.get("online_lookup"):
                        evidence_result["status"] = "already_processed"
                        source = "local database" if lookup_result.get("local_lookup") else "VirusTotal"
                        evidence_result["message"] = f"File hash found in {source}. Analysis copied/populated."
                        logger.info(f"Hash found in {source}. Skipping further processing.")
                        await self.filescanner_repo.store_analysis_results(complaint_id, evidence_id, evidence_result)
                        overall_results["evidences_processed"] += 1
                        overall_results["evidence_results"].append(evidence_result)
                        continue

                    mime_result, entropy_result, clam_av_result, yara_result = await asyncio.gather(
                        self.mime_sniffing_service.sniff_mime(file_data, filename=file_name, claimed_mime=file_name_extension),
                        self.file_entropy_service.calculate_entropy(file_data),
                        self.clam_av_service.scan(file_data),
                        self.yara_scan_service.scan_full(file_data)
                    )

                    evidence_result["mime_type"] = mime_result
                    evidence_result["entropy"] = entropy_result
                    evidence_result["clam_av"] = clam_av_result
                    evidence_result["yara_scan"] = yara_result

                    file_extension = mime_result.get("extension")
                    file_category = mime_result.get("category")

                    if file_category in self.processors:
                        processor = self.processors[file_category]
                        processor_result = processor.process(file_data, file_extension)
                        if asyncio.iscoroutine(processor_result):
                            processor_result = await processor_result
                        evidence_result["file_type_analysis"] = processor_result

                    final_report = await self.report_generator_service.generate_report(evidence_result)
                    evidence_result["final_report"] = final_report
                    evidence_result["status"] = "completed"

                    await self.filescanner_repo.store_analysis_results(complaint_id, evidence_id, evidence_result)
                    overall_results["evidences_processed"] += 1

                except Exception as evidence_error:
                    evidence_result["status"] = "failed"
                    evidence_result["error"] = str(evidence_error)
                    overall_results["evidences_failed"] += 1
                    try:
                        await self.filescanner_repo.store_analysis_results(complaint_id, evidence_id, evidence_result)
                    except Exception as store_error:
                        logger.error(f"Failed to store error results: {store_error}")

                overall_results["evidence_results"].append(evidence_result)

            if overall_results["evidences_failed"] == 0:
                overall_results["overall_status"] = "completed"
            elif overall_results["evidences_processed"] > 0:
                overall_results["overall_status"] = "partially_completed"
            else:
                overall_results["overall_status"] = "failed"

            logger.info(
                f"Completed processing for complaint_id: {complaint_id}. "
                f"Processed: {overall_results['evidences_processed']}, "
                f"Failed: {overall_results['evidences_failed']}"
            )

            return overall_results

        except Exception as workflow_error:
            logger.error(f"Error processing evidences for complaint_id {complaint_id}: {workflow_error}")
            overall_results["overall_status"] = "failed"
            overall_results["error"] = str(workflow_error)
            return overall_results

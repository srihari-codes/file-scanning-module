from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo.errors import PyMongoError

from config.settings import settings
from database.complaints_master_table import ComplaintsMasterTableRepository
from database.filescanner_microservice_table import FilescannerMicroserviceTableRepository
from utils.logger import get_logger

logger = get_logger(__name__)


class DatabaseManager:
    def __init__(self) -> None:
        self.client: Optional[AsyncIOMotorClient] = None
        self.db: Optional[AsyncIOMotorDatabase] = None
        self.complaints: ComplaintsMasterTableRepository
        self.filescanner: FilescannerMicroserviceTableRepository
        self._connect()

    def _connect(self) -> None:
        """Initialize MongoDB connection and repositories."""
        try:
            self.client = AsyncIOMotorClient(settings.MONGODB_URL)
            self.db = self.client[settings.MONGODB_DB_NAME]

            complaints_collection = self.db[settings.MONGODB_READ_COLLECTION]
            filescanner_collection = self.db[settings.MONGODB_WRITE_COLLECTION]

            self.complaints = ComplaintsMasterTableRepository(complaints_collection)
            self.filescanner = FilescannerMicroserviceTableRepository(filescanner_collection)

            logger.info(
                "Connected to MongoDB: %s (read: %s, write: %s)",
                settings.MONGODB_DB_NAME,
                settings.MONGODB_READ_COLLECTION,
                settings.MONGODB_WRITE_COLLECTION,
            )
        except PyMongoError as exc:
            logger.error("Failed to connect to MongoDB: %s", exc)
            raise

    async def get_evidence_ids(self, complaint_id: str) -> List[str]:
        return await self.complaints.get_evidence_ids(complaint_id)

    async def get_analysis_status(self, complaint_id: str) -> Optional[Dict[str, Any]]:
        return await self.complaints.get_analysis_status(complaint_id)

    async def store_analysis_results(
        self, complaint_id: str, evidence_id: str, results: Dict[str, Any]
    ) -> bool:
        return await self.filescanner.store_analysis_results(
            complaint_id, evidence_id, results
        )

    async def add_file_hash(
        self, complaint_id: str, evidence_id: str, hash_value: str
    ) -> bool:
        return await self.filescanner.add_file_hash(complaint_id, evidence_id, hash_value)

    async def close(self) -> None:
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed")

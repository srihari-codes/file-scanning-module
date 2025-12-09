from typing import Any, Dict, List, Tuple
from urllib.parse import urljoin

import aiohttp

from config.settings import settings
from utils.logger import get_logger

logger = get_logger(__name__)


class FileDataService:
	"""Service for retrieving evidence files from Supabase storage."""

	def __init__(self) -> None:
		self._base_url = settings.SUPABASE_URL.rstrip("/")
		self._bucket = settings.SUPABASE_BUCKET.strip("/")
		self._public_object_base = (
			f"{self._base_url}/storage/v1/object/public/{self._bucket}".rstrip("/") + "/"
		)
		self._headers = {
			"apikey": settings.SUPABASE_KEY,
			"Authorization": f"Bearer {settings.SUPABASE_KEY}",
		}
		self._timeout = aiohttp.ClientTimeout(total=60)

	async def fetch_file_data(self, complaint_id: str, evidence_id: str) -> List[Tuple[str, bytes]]:
		"""
		Retrieve ALL evidence files for the given complaint/evidence identifiers.

		Returns:
			List of tuples (file_name, file_bytes)
		"""
		prefix = self._build_prefix(complaint_id, evidence_id)

		async with aiohttp.ClientSession(timeout=self._timeout) as session:
			file_entries = await self._fetch_all_file_entries(session, prefix)

			if not file_entries:
				logger.error("No files found in Supabase | prefix=%s", prefix)
				raise RuntimeError("No evidence files found in Supabase")

			results: List[Tuple[str, bytes]] = []

			for entry in file_entries:
				entry_name = entry.get("name")

				if not isinstance(entry_name, str) or not entry_name:
					logger.warning("Skipping invalid entry | prefix=%s | entry=%s", prefix, entry)
					continue

				object_path = self._build_object_path(prefix, entry_name)
				file_name = object_path.split("/")[-1]

				file_bytes = await self._download_object(session, object_path)

				results.append((file_name, file_bytes))

			return results

	def _build_prefix(self, complaint_id: str, evidence_id: str) -> str:
		return f"complaints/{complaint_id}/evidences/{evidence_id}".strip("/")

	async def _fetch_all_file_entries(self, session: aiohttp.ClientSession, prefix: str) -> List[Dict[str, Any]]:
		list_url = f"{self._base_url}/storage/v1/object/list/{self._bucket}"
		payload = {
			"prefix": prefix,
			"limit": 100,
			"offset": 0,
			"sortBy": {"column": "name", "order": "asc"},
		}

		async with session.post(list_url, headers=self._headers, json=payload) as response:
			if response.status != 200:
				body = await response.text()
				logger.error(
					"Supabase list request failed | status=%s | prefix=%s | body=%s",
					response.status,
					prefix,
					body,
				)
				raise RuntimeError("Failed to list evidence files from Supabase")

			try:
				entries = await response.json(content_type=None)
			except (aiohttp.ContentTypeError, ValueError) as error:
				body = await response.text()
				logger.error(
					"Supabase list response parse error | prefix=%s | body=%s",
					prefix,
					body,
				)
				raise RuntimeError("Unable to parse Supabase list response") from error

		if not isinstance(entries, list):
			logger.error("Unexpected Supabase list response structure | prefix=%s | body=%s", prefix, entries)
			raise RuntimeError("Unexpected response while listing Supabase objects")

		files = [
			entry
			for entry in entries
			if isinstance(entry, dict)
			and entry.get("id")
			and entry.get("metadata", {}).get("size", 0) > 0
		]

		if not files:
			logger.warning("No evidence files found at prefix=%s", prefix)

		return files

	def _build_object_path(self, prefix: str, entry_name: str) -> str:
		clean_prefix = prefix.strip("/")
		clean_name = entry_name.strip("/")

		if clean_name.startswith(clean_prefix):
			return clean_name

		return f"{clean_prefix}/{clean_name}".strip("/")

	async def _download_object(self, session: aiohttp.ClientSession, object_path: str) -> bytes:
		download_url = urljoin(self._public_object_base, object_path.lstrip("/"))

		async with session.get(download_url, headers=self._headers) as response:
			if response.status == 404:
				logger.warning("Evidence file missing during download | path=%s", object_path)
				raise FileNotFoundError("Evidence file not found in Supabase storage")

			if response.status != 200:
				body = await response.text()
				logger.error(
					"Supabase download failed | status=%s | path=%s | body=%s",
					response.status,
					object_path,
					body,
				)
				raise RuntimeError("Failed to download evidence file from Supabase")

			return await response.read()

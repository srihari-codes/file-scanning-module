
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from typing import Any, Dict, List

_ASCII_FALLBACK = re.compile(rb"[ -~]{4,}")
_PACKAGE_RE = re.compile(r'package="([^"]+)"')
_VERSION_RE = re.compile(r'version(Name|Code)="([^"]+)"', re.IGNORECASE)
_PERMISSION_RE = re.compile(r'uses-permission(?:\s+android:name)?="([^"]+)"', re.IGNORECASE)
_COMPONENT_RE = re.compile(r'<(activity|service|receiver|provider)[^>]+android:name="([^"]+)"', re.IGNORECASE)
_SDK_RE = re.compile(r'(minSdkVersion|maxSdkVersion|targetSdkVersion)="?([0-9]+)"?', re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)


class ApkProcessor:
	"""Best-effort APK analyzer that only relies on the Python standard library."""

	@classmethod
	def process(cls, file_data: bytes, file_extension: str | None = None) -> Dict[str, Any]:
		data = file_data or b""
		report = cls._empty_report()
		report["metadata"].update(
			{
				"sha256": hashlib.sha256(data).hexdigest(),
				"file_size": len(data),
				"extension": (file_extension or "").lstrip(".").lower(),
			}
		)

		if not data:
			report["verdict"] = "empty_blob"
			return report

		bio = io.BytesIO(data)
		if not zipfile.is_zipfile(bio):
			report["verdict"] = "not_apk_like"
			return report
		bio.seek(0)

		with zipfile.ZipFile(bio) as zf:
			names = zf.namelist()
			report["structure"].update(
				{
					"entry_count": len(names),
					"dex_files": [n for n in names if n.endswith(".dex")],
					"lib_entries": [n for n in names if n.startswith("lib/") and n.endswith(".so")],
					"asset_entries": [n for n in names if n.startswith("assets/")],
					"has_v1_signature": any(n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC")) for n in names),
					"sample_entries": names[:15],
				}
			)

			manifest_text = cls._load_manifest(zf)
			manifest_info = cls._parse_manifest(manifest_text)
			report["metadata"].update(
				{
					"package_name": manifest_info.get("package"),
					"version_name": manifest_info.get("version_name"),
					"version_code": manifest_info.get("version_code"),
					"sdk_info": manifest_info.get("sdk"),
				}
			)

			report["indicators"].update(
				{
					"permissions": manifest_info.get("permissions", []),
					"components": manifest_info.get("components", {}),
					"urls": cls._extract_urls(manifest_text),
				}
			)

			report["feature_vector"]["numeric_features"] = {
				"permission_count": len(manifest_info.get("permissions", [])),
				"dex_count": len(report["structure"].get("dex_files", [])),
				"embedded_native_libs": len(report["structure"].get("lib_entries", [])),
				"asset_count": len(report["structure"].get("asset_entries", [])),
			}

		report["verdict"] = "apk_archive"
		report["confidence"]["overall_confidence"] = 0.4 if report["metadata"].get("package_name") else 0.2
		return report

	@staticmethod
	def _empty_report() -> Dict[str, Any]:
		return {
			"verdict": "unclassified",
			"metadata": {
				"sha256": None,
				"file_size": 0,
				"extension": None,
				"package_name": None,
				"version_name": None,
				"version_code": None,
				"sdk_info": {},
			},
			"structure": {
				"entry_count": 0,
				"dex_files": [],
				"lib_entries": [],
				"asset_entries": [],
				"sample_entries": [],
				"has_v1_signature": False,
			},
			"entities": {
				"named_entities": [],
				"pii_summary": {},
			},
			"indicators": {
				"permissions": [],
				"components": {},
				"urls": [],
			},
			"nlp": {},
			"confidence": {
				"overall_confidence": 0.0,
			},
			"feature_vector": {
				"numeric_features": {},
			},
		}

	@staticmethod
	def _load_manifest(zf: zipfile.ZipFile) -> str:
		try:
			raw = zf.read("AndroidManifest.xml")
		except KeyError:
			return ""
		for encoding in ("utf-8", "utf-16", "utf-16le", "utf-16be"):
			try:
				return raw.decode(encoding)
			except UnicodeDecodeError:
				continue
		ascii_chunks = _ASCII_FALLBACK.findall(raw)
		return "\n".join(chunk.decode("utf-8", errors="ignore") for chunk in ascii_chunks)

	@staticmethod
	def _parse_manifest(text: str) -> Dict[str, Any]:
		if not text:
			return {
				"package": None,
				"version_name": None,
				"version_code": None,
				"permissions": [],
				"components": {},
				"sdk": {},
			}

		package_match = _PACKAGE_RE.search(text)
		version_name = None
		version_code = None
		for match in _VERSION_RE.finditer(text):
			key = match.group(1).lower()
			value = match.group(2)
			if key == "name":
				version_name = value
			else:
				version_code = value

		permissions = sorted({m.group(1) for m in _PERMISSION_RE.finditer(text)})
		components: Dict[str, List[str]] = {}
		for ctype, name in _COMPONENT_RE.findall(text):
			bucket = components.setdefault(ctype.lower(), [])
			bucket.append(name)

		sdk_info: Dict[str, Any] = {}
		for key, value in _SDK_RE.findall(text):
			sdk_info[key] = int(value)

		return {
			"package": package_match.group(1) if package_match else None,
			"version_name": version_name,
			"version_code": version_code,
			"permissions": permissions,
			"components": components,
			"sdk": sdk_info,
		}

	@staticmethod
	def _extract_urls(manifest_text: str) -> List[str]:
		if not manifest_text:
			return []
		urls = _URL_RE.findall(manifest_text)
		dedup: List[str] = []
		for url in urls:
			if url not in dedup:
				dedup.append(url)
			if len(dedup) >= 10:
				break
		return dedup

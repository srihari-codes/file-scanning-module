
from __future__ import annotations

import hashlib
import math
import re
import struct
from datetime import datetime, timezone
from typing import Any, Dict, List

_ASCII_STRING_RE = re.compile(rb"[ -~]{6,}")
_COMMON_APIS = [
	"CreateProcessA",
	"CreateProcessW",
	"WinExec",
	"ShellExecuteA",
	"ShellExecuteW",
	"URLDownloadToFileA",
	"URLDownloadToFileW",
	"InternetOpenA",
	"InternetConnectA",
	"HttpSendRequestA",
	"VirtualAlloc",
	"VirtualProtect",
	"LoadLibraryA",
	"LoadLibraryW",
	"GetProcAddress",
]
_SUSPICIOUS_KEYWORDS = [
	"powershell",
	"cmd.exe",
	"http://",
	"https://",
	"runas",
	"schtasks",
	"certutil",
	"regsvr32",
	".onion",
]


class ExecutableProcessor:
	"""Lightweight PE/portable binary summarizer used by the workflow."""

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
			report["verdict"] = "empty_binary"
			return report

		pe_info = cls._parse_pe(data)
		if pe_info["detected"]:
			report["verdict"] = "pe_binary"
			report["metadata"].update(pe_info["header"])
			report["structure"].update(pe_info["structure"])
			report["indicators"]["imports"] = pe_info["imports"]
		else:
			report["verdict"] = "unknown_binary"

		report["indicators"]["suspicious_strings"] = cls._suspicious_strings(data)
		report["feature_vector"]["numeric_features"] = cls._feature_vector(data, pe_info)
		report["confidence"]["overall_confidence"] = 0.35 if pe_info["detected"] else 0.15
		return report

	@staticmethod
	def _empty_report() -> Dict[str, Any]:
		return {
			"verdict": "unclassified",
			"metadata": {
				"sha256": None,
				"file_size": 0,
				"extension": None,
			},
			"structure": {
				"sections": [],
			},
			"entities": {
				"named_entities": [],
				"pii_summary": {},
			},
			"indicators": {
				"imports": [],
				"suspicious_strings": [],
			},
			"nlp": {},
			"confidence": {
				"overall_confidence": 0.0,
			},
			"feature_vector": {
				"numeric_features": {},
			},
		}

	@classmethod
	def _parse_pe(cls, data: bytes) -> Dict[str, Any]:
		info: Dict[str, Any] = {
			"detected": False,
			"header": {},
			"structure": {"sections": []},
			"imports": [],
		}
		if len(data) < 0x40 or not data.startswith(b"MZ"):
			return info
		try:
			pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
			if pe_offset + 24 > len(data):
				return info
			if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
				return info

			info["detected"] = True
			machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
			section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
			timestamp = struct.unpack_from("<I", data, pe_offset + 8)[0]
			optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
			optional_offset = pe_offset + 24
			optional_blob = data[optional_offset : optional_offset + optional_size]

			header: Dict[str, Any] = {
				"machine": cls._machine_name(machine),
				"timestamp_utc": cls._format_timestamp(timestamp),
			}
			entry_point = None
			image_base = None
			size_of_image = None
			subsystem = None
			dll_characteristics = None

			if len(optional_blob) >= 2:
				magic = struct.unpack_from("<H", optional_blob, 0)[0]
				is_pe_plus = magic == 0x20B
				try:
					entry_point = struct.unpack_from("<I", optional_blob, 16)[0]
				except struct.error:
					entry_point = None
				try:
					if is_pe_plus:
						image_base = struct.unpack_from("<Q", optional_blob, 24)[0]
					else:
						image_base = struct.unpack_from("<I", optional_blob, 28)[0]
				except struct.error:
					image_base = None
				try:
					size_of_image = struct.unpack_from("<I", optional_blob, 56)[0]
				except struct.error:
					size_of_image = None
				try:
					subsystem = struct.unpack_from("<H", optional_blob, 68)[0]
				except struct.error:
					subsystem = None
				try:
					dll_characteristics = struct.unpack_from("<H", optional_blob, 70)[0]
				except struct.error:
					dll_characteristics = None

			header.update(
				{
					"entry_point_rva": hex(entry_point) if entry_point is not None else None,
					"image_base": hex(image_base) if image_base is not None else None,
					"size_of_image": size_of_image,
					"subsystem": subsystem,
					"dll_characteristics": hex(dll_characteristics)
					if dll_characteristics is not None
					else None,
				}
			)
			info["header"] = header

			section_table_offset = optional_offset + optional_size
			sections: List[Dict[str, Any]] = []
			for idx in range(section_count):
				start = section_table_offset + idx * 40
				end = start + 40
				if end > len(data):
					break
				name_bytes = data[start : start + 8]
				name = name_bytes.split(b"\x00", 1)[0].decode("ascii", errors="ignore") or f"sec_{idx}"
				virtual_size = struct.unpack_from("<I", data, start + 8)[0]
				virtual_address = struct.unpack_from("<I", data, start + 12)[0]
				raw_size = struct.unpack_from("<I", data, start + 16)[0]
				raw_pointer = struct.unpack_from("<I", data, start + 20)[0]
				characteristics = struct.unpack_from("<I", data, start + 36)[0]
				slice_end = min(len(data), raw_pointer + min(raw_size, 65536))
				section_blob = data[raw_pointer:slice_end] if raw_pointer < len(data) else b""
				sections.append(
					{
						"name": name,
						"virtual_size": virtual_size,
						"virtual_address": hex(virtual_address),
						"raw_size": raw_size,
						"characteristics": hex(characteristics),
						"entropy": cls._shannon_entropy(section_blob) if section_blob else 0.0,
					}
				)

			info["structure"] = {
				"section_count": len(sections),
				"entry_point_rva": header.get("entry_point_rva"),
				"sections": sections,
			}
			info["imports"] = cls._guess_api_usage(data)
			return info
		except (struct.error, ValueError):
			return info

	@staticmethod
	def _machine_name(machine: int) -> str:
		mapping = {
			0x14C: "x86",
			0x8664: "x64",
			0xAA64: "arm64",
			0x1C0: "arm",
		}
		return mapping.get(machine, hex(machine))

	@staticmethod
	def _format_timestamp(timestamp: int) -> str | None:
		if not timestamp:
			return None
		try:
			return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
		except (OverflowError, OSError, ValueError):
			return None

	@staticmethod
	def _guess_api_usage(data: bytes) -> List[str]:
		hits: List[str] = []
		for api in _COMMON_APIS:
			if api.encode("ascii") in data:
				hits.append(api)
			if len(hits) >= 20:
				break
		return hits

	@classmethod
	def _suspicious_strings(cls, data: bytes) -> List[str]:
		matches = _ASCII_STRING_RE.findall(data)
		interesting: List[str] = []
		for raw in matches:
			lower = raw.lower()
			if any(keyword.encode("ascii") in lower for keyword in _SUSPICIOUS_KEYWORDS):
				try:
					decoded = raw.decode("utf-8")
				except UnicodeDecodeError:
					decoded = raw.decode("latin-1", errors="ignore")
				if decoded not in interesting:
					interesting.append(decoded)
			if len(interesting) >= 10:
				break
		return interesting

	@classmethod
	def _feature_vector(cls, data: bytes, pe_info: Dict[str, Any]) -> Dict[str, Any]:
		sections = pe_info.get("structure", {}).get("sections", [])
		return {
			"file_size": len(data),
			"entropy": round(cls._shannon_entropy(data), 4) if data else 0.0,
			"section_count": len(sections),
			"api_hits": len(pe_info.get("imports", [])),
		}

	@staticmethod
	def _shannon_entropy(blob: bytes) -> float:
		if not blob:
			return 0.0
		counts = {}
		for b in blob:
			counts[b] = counts.get(b, 0) + 1
		length = len(blob)
		entropy = 0.0
		for count in counts.values():
			p = count / length
			entropy -= p * math.log2(p)
		return entropy

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

try:  # pragma: no cover - import guard
	import yara  # type: ignore
except ImportError:  # pragma: no cover - handled gracefully later
	yara = None

YaraErrorType = Exception
YaraTimeoutErrorType = TimeoutError

if yara is not None:  # pragma: no cover - depends on yara runtime
	try:
		YaraErrorType = yara.Error  # type: ignore[attr-defined]
		YaraTimeoutErrorType = yara.TimeoutError  # type: ignore[attr-defined]
	except AttributeError:
		pass

from utils.logger import get_logger
from services.mime_sniffing import MimeSniffingService


logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class YaraServiceError(Exception):
	"""Base class for YARA service exceptions with structured payload."""

	def __init__(self, message: str, *, code: str, details: Optional[Dict[str, Any]] = None) -> None:
		super().__init__(message)
		self.code = code
		self.details = details or {}

	def to_dict(self) -> Dict[str, Any]:
		return {"error_code": self.code, "message": str(self), "details": self.details}


class YaraUnavailableError(YaraServiceError):
	def __init__(self) -> None:
		super().__init__(
			"yara-python is not installed. Install the dependency to enable scanning.",
			code="YARA_LIBRARY_MISSING",
		)


class YaraCompilationError(YaraServiceError):
	pass


class YaraExecutionError(YaraServiceError):
	pass


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class RuleSource:
	"""Represents a single YARA rule file and its associated namespace."""

	namespace: str
	path: Path


@dataclass
class RuleMetadata:
	"""Captured details about compiled YARA rules for downstream analysis."""

	rule_name: str
	namespace: str
	tags: Sequence[str] = field(default_factory=list)
	meta: Dict[str, Any] = field(default_factory=dict)
	category_hints: Sequence[str] = field(default_factory=list)


@dataclass
class MatchString:
	identifier: str
	value: str
	offset: int


@dataclass
class MatchRecord:
	rule_name: str
	namespace: str
	tags: Sequence[str]
	matched_strings: List[MatchString]
	metadata: Dict[str, Any]
	severity: str
	family: Optional[str]


@dataclass
class FilePreprocessContext:
	"""Holds metadata about a file before scanning."""

	filename: Optional[str]
	file_size: int
	sha256: str
	mime_result: Dict[str, Any]
	buffers: List[bytes]
	received_at: str


# ---------------------------------------------------------------------------
# Constants and taxonomy helpers
# ---------------------------------------------------------------------------


BUILT_IN_RULE_CATEGORIES: Dict[str, str] = {
	"windows_malware": "windows_malware_families",
	"ransomware": "ransomware_families",
	"spyware": "spyware_stealer_signatures",
	"worms": "worm_signatures",
	"indian_banking": "indian_banking_malware",
	"apt": "apt_indicator_signatures",
}

CUSTOM_RULE_CATEGORIES: Dict[str, str] = {
	"espionage": "espionage_indicators",
	"targeted_attack": "targeted_attack_indicators",
	"defence_phishing": "defence_personnel_phishing_patterns",
	"honeytrap": "honeytrap_behavioural_patterns",
	"opsec_breach": "opsec_breach_artefacts",
}

CATEGORY_ALIASES: Dict[str, Sequence[str]] = {
	"malware": ("malware", "windows_malware", "windows_malware_families"),
	"ransomware": ("ransomware", "ransomware_families"),
	"phishing": ("phishing", "defence_phishing", "phishing_artifacts", "phishing artefacts"),
	"apt": ("apt", "apt_indicator_signatures", "espionage", "targeted_attack"),
	"steganography": ("steganographic", "steganographic_patterns"),
	"obfuscation": ("obfuscation", "packed", "packer", "obfuscation_cipher_patterns"),
}

ALLOWED_METADATA_KEYS = {"author", "description", "reference", "family", "severity"}

PACKER_SECTION_HINTS = {
	"upx",
	"mpress",
	"aspack",
	"petite",
	"pecompact",
	"pack",
	"vmp",
	"vmprotect",
	"themida",
}

SEVERITY_KEYWORDS: Dict[str, str] = {
	"ransom": "high",
	"spyware": "high",
	"stealer": "high",
	"agenttesla": "high",
	"nanocore": "high",
	"lokibot": "high",
	"remcos": "high",
	"cobaltstrike": "high",
	"packed": "medium",
	"suspicious_import": "medium",
	"phishing": "medium",
	"obfuscation": "medium",
	"miner": "medium",
	"cryptominer": "medium",
	"heuristic": "medium",
}

# Maps known indicators to malware taxonomy families
FAMILY_KEYWORDS: Dict[str, str] = {
	"agenttesla": "AgentTesla",
	"nanocore": "Nanocore RAT",
	"lokibot": "Lokibot",
	"remcos": "Remcos RAT",
	"gif_shell": "GIF-shell phishing trick",
	"gif-shell": "GIF-shell phishing trick",
	"zloader": "ZLoader",
	"cobaltstrike": "CobaltStrike beacon indicators",
}

HEURISTIC_TAGS = {"entropy", "packed", "packer", "c2", "command_and_control", "obfuscation", "heuristic", "suspicious_imports"}


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def _build_default_rule_paths(base_dir: Path, catalogue: Dict[str, str]) -> List[RuleSource]:
	sources: List[RuleSource] = []
	for namespace, folder in catalogue.items():
		folder_path = base_dir / folder
		if not folder_path.exists():
			logger.warning("Rule directory missing for namespace %s: %s", namespace, folder_path)
			continue
		for extension in ("*.yar", "*.yara"):
			for rule_file in folder_path.rglob(extension):
				sources.append(RuleSource(namespace=namespace, path=rule_file))
	return sources


def _stringify_match_data(data: Any) -> str:
	if isinstance(data, bytes):
		try:
			return data.decode("utf-8", errors="strict")
		except UnicodeDecodeError:
			return data.hex()
	if isinstance(data, (str, int)):
		return str(data)
	return json.dumps(data, ensure_ascii=True)


def _normalize_category_name(name: str) -> str:
	return name.strip().lower().replace(" ", "_")


def _collect_root_rule_sources(base_dir: Path, *, namespace_root: str) -> List[RuleSource]:
	sources: List[RuleSource] = []
	if not base_dir.exists():
		return sources
	root_files: Set[Path] = set()
	for extension in ("*.yar", "*.yara"):
		root_files.update(base_dir.glob(extension))
	for rule_file in sorted(root_files):
		namespace_suffix = _normalize_category_name(rule_file.stem) or "root"
		namespace = f"{namespace_root}_{namespace_suffix}"
		sources.append(RuleSource(namespace=namespace, path=rule_file))
	return sources


def _select_categories(requested: Optional[Sequence[str]]) -> Optional[Sequence[str]]:
	if not requested:
		return None
	resolved: List[str] = []
	for entry in requested:
		normalized = _normalize_category_name(entry)
		resolved.append(normalized)
		for alias, values in CATEGORY_ALIASES.items():
			alias_normalized = _normalize_category_name(alias)
			alias_bucket = {_normalize_category_name(value) for value in values}
			alias_bucket.add(alias_normalized)
			if normalized in alias_bucket:
				resolved.append(alias_normalized)
	return list(dict.fromkeys(resolved))


def _infer_severity(rule_name: str, tags: Sequence[str]) -> str:
	base = "low"
	haystack = " ".join([rule_name.lower(), *[t.lower() for t in tags]])
	for keyword, severity in SEVERITY_KEYWORDS.items():
		if keyword in haystack:
			if severity == "high":
				return "high"
			base = severity
	return base


def _infer_family(rule_name: str, tags: Sequence[str]) -> Optional[str]:
	haystack = " ".join([rule_name.lower(), *[t.lower() for t in tags]])
	for keyword, family in FAMILY_KEYWORDS.items():
		if keyword in haystack:
			return family
	return None


def _highest_severity(severities: Iterable[str]) -> str:
	ranking = {"low": 1, "medium": 2, "high": 3}
	highest = "low"
	for severity in severities:
		current = severity.lower()
		if ranking.get(current, 0) > ranking.get(highest, 0):
			highest = current
	return highest


def _suggest_next_step(highest_severity: str) -> str:
	return {
		"high": "sandbox_dynamic_analysis",
		"medium": "static_followup",
		"low": "manual_review",
	}.get(highest_severity.lower(), "manual_review")


def _sanitize_string(value: str, *, max_length: int = 2048) -> str:
	text = "".join(ch for ch in value if ch.isprintable())
	if max_length > 0 and len(text) > max_length:
		return text[:max_length]
	return text


def _sanitize_metadata(meta: Mapping[str, Any]) -> Dict[str, Any]:
	sanitized: Dict[str, Any] = {}
	for key in ALLOWED_METADATA_KEYS:
		if key not in meta:
			continue
		value = meta[key]
		if isinstance(value, str):
			sanitized[key] = _sanitize_string(value)
		elif isinstance(value, (int, float)):
			sanitized[key] = value
	return sanitized


def _expand_category_aliases(category: str) -> Set[str]:
	category_normalized = _normalize_category_name(category)
	aliases: Set[str] = {category_normalized}
	for alias, values in CATEGORY_ALIASES.items():
		alias_normalized = _normalize_category_name(alias)
		value_normalized = {_normalize_category_name(value) for value in values}
		if category_normalized == alias_normalized or category_normalized in value_normalized:
			aliases.add(alias_normalized)
			aliases.update(value_normalized)
	return aliases


def _derive_rule_categories(namespace: str, tags: Sequence[str], metadata: Mapping[str, Any]) -> Set[str]:
	categories: Set[str] = set()
	if namespace:
		categories.update(_expand_category_aliases(namespace))
	for tag in tags:
		categories.update(_expand_category_aliases(tag))
	for value in metadata.values():
		if isinstance(value, str):
			categories.update(_expand_category_aliases(value))
	return {category for category in categories if category}


# ---------------------------------------------------------------------------
# Main service implementation
# ---------------------------------------------------------------------------


class YaraScanService:
	"""Coordinates loading, compilation, preprocessing, scanning, and analysis."""

	def __init__(
		self,
		*,
		built_in_root: Optional[Path] = None,
		custom_root: Optional[Path] = None,
		chunk_size: int = 4 * 1024 * 1024,
		enable_hot_reload: bool = True,
		mime_sniffer: Optional[MimeSniffingService] = None,
		match_timeout_ms: Optional[int] = 2000,
		max_match_records: int = 500,
	) -> None:
		self._ensure_yara_available()
		self.built_in_root = built_in_root or (Path(__file__).resolve().parent / ".." / "rules" / "built_in").resolve()
		self.custom_root = custom_root or (Path(__file__).resolve().parent / ".." / "rules" / "custom").resolve()
		self.chunk_size = chunk_size
		self.enable_hot_reload = enable_hot_reload
		self.mime_sniffer = mime_sniffer or MimeSniffingService()
		self.match_timeout_ms = match_timeout_ms
		self.max_match_records = max_match_records

		self._compiled_rules: Optional[Any] = None
		self._rule_registry: Dict[str, RuleMetadata] = {}
		self._rule_sources: List[RuleSource] = []
		self._rule_categories: Dict[str, Set[str]] = {}
		self._category_to_rules: Dict[str, Set[str]] = {}
		self._lock = asyncio.Lock()
		self._last_loaded_at: Optional[datetime] = None

		logger.info("Load your arsenal before shooting – initializing YARA rule corpus")
		self._load_rules_sync()

	# ------------------------------------------------------------------
	# Rule loading and compilation
	# ------------------------------------------------------------------

	def _ensure_yara_available(self) -> None:
		if yara is None:
			raise YaraUnavailableError()

	def _load_rules_sync(self) -> None:
		try:
			yara_module = yara
			if yara_module is None:  # pragma: no cover - safety
				raise YaraUnavailableError()

			self._rule_sources = self._discover_rules()
			if not self._rule_sources:
				logger.warning("No YARA rules discovered; compiled ruleset will be empty")
				self._compiled_rules = yara_module.compile(source="rule Dummy { condition: false }")
				self._rule_registry.clear()
				self._rule_categories.clear()
				self._category_to_rules.clear()
				return

			filepaths = {f"{src.namespace}_{idx}": str(src.path) for idx, src in enumerate(self._rule_sources)}
			try:
				compiled = yara_module.compile(filepaths=filepaths)
			except YaraErrorType as exc:  # pragma: no cover - depends on runtime rules
				raise YaraCompilationError(
					f"Failed to compile YARA rules: {exc}",
					code="YARA_COMPILATION_FAILED",
					details={"filepaths": filepaths},
				) from exc

			duplicates = self._detect_duplicate_rules(compiled)
			if duplicates:
				raise YaraCompilationError(
					"Duplicate YARA rules detected",
					code="YARA_DUPLICATE_RULE",
					details={"duplicates": sorted(duplicates)},
				)

			self._compiled_rules = compiled
			self._rule_registry = self._extract_rule_registry(compiled)
			self._last_loaded_at = datetime.now(timezone.utc)
			logger.info(
				"Successfully compiled %s YARA rules across %s namespaces (idempotent load)",
				len(self._rule_registry),
				len({meta.namespace for meta in self._rule_registry.values()}),
			)
		except YaraServiceError:
			raise
		except Exception as exc:  # pragma: no cover - defensive
			raise YaraCompilationError(
				f"Unexpected error compiling YARA rules: {exc}",
				code="YARA_COMPILATION_UNEXPECTED",
			) from exc

	def _discover_rules(self) -> List[RuleSource]:
		sources: List[RuleSource] = []
		sources.extend(_collect_root_rule_sources(self.built_in_root, namespace_root="built_in"))
		sources.extend(_build_default_rule_paths(self.built_in_root, BUILT_IN_RULE_CATEGORIES))
		sources.extend(_collect_root_rule_sources(self.custom_root, namespace_root="custom"))
		sources.extend(_build_default_rule_paths(self.custom_root, CUSTOM_RULE_CATEGORIES))
		return sources

	def _detect_duplicate_rules(self, compiled: Any) -> List[str]:  # pragma: no cover - relies on rules
		seen: Dict[str, str] = {}
		duplicates: List[str] = []
		rules_iterable = getattr(compiled, "rules", None)
		if rules_iterable is None:
			rules_iterable = getattr(compiled, "__iter__", None)
			if callable(rules_iterable):
				rules_iterable = compiled
			else:
				rules_iterable = []
		try:
			for rule in rules_iterable:
				rule_name = getattr(rule, "rule", getattr(rule, "identifier", ""))
				if not rule_name:
					continue
				namespace = getattr(rule, "namespace", "") or ""
				if rule_name in seen and seen[rule_name] != namespace:
					duplicates.append(rule_name)
				else:
					seen[rule_name] = namespace
		except TypeError:
			logger.debug("Compiled rules object is not iterable – skip duplicate inspection")
		return duplicates

	def _extract_rule_registry(self, compiled: Any) -> Dict[str, RuleMetadata]:  # pragma: no cover - relies on rules
		registry: Dict[str, RuleMetadata] = {}
		rule_categories: Dict[str, Set[str]] = {}
		category_to_rules: Dict[str, Set[str]] = {}
		rules_iterable = getattr(compiled, "rules", None)
		if rules_iterable is None:
			rules_iterable = compiled
		try:
			for rule in rules_iterable:
				name = getattr(rule, "rule", getattr(rule, "identifier", ""))
				if not name:
					continue
				namespace = getattr(rule, "namespace", "") or ""
				tags = tuple(getattr(rule, "tags", ()) or ())
				raw_meta = dict(getattr(rule, "meta", {}) or {})
				sanitized_meta = _sanitize_metadata(raw_meta)
				hints: List[str] = list(tags)
				hints.extend(value for value in sanitized_meta.values() if isinstance(value, str))
				metadata = RuleMetadata(
					rule_name=name,
					namespace=namespace,
					tags=tags,
					meta=sanitized_meta,
					category_hints=hints,
				)
				registry[name] = metadata
				categories = _derive_rule_categories(namespace, tags, sanitized_meta)
				rule_categories[name] = categories
				for category in categories:
					category_to_rules.setdefault(category, set()).add(name)
		except TypeError:
			logger.debug("Compiled rules object is not iterable – registry limited")
		self._rule_categories = rule_categories
		self._category_to_rules = category_to_rules
		return registry

	async def reload_rules(self) -> None:
		if not self.enable_hot_reload:
			logger.info("Hot reload disabled – skipping rule compilation refresh")
			return
		async with self._lock:
			logger.info("Hot reloading YARA rules without killing the microservice")
			self._load_rules_sync()

	# ------------------------------------------------------------------
	# File preprocessing
	# ------------------------------------------------------------------

	async def preprocess_file(self, file_data: bytes, *, filename: Optional[str] = None, claimed_mime: Optional[str] = None) -> FilePreprocessContext:
		"""Prepare buffers, metadata, and MIME insight before scanning."""

		if not isinstance(file_data, (bytes, bytearray)):
			raise ValueError("file_data must be bytes-like")

		file_bytes = bytes(file_data)
		file_size = len(file_bytes)
		sha256 = hashlib.sha256(file_bytes).hexdigest()
		received_at = datetime.now(timezone.utc).isoformat()

		mime_result = await self.mime_sniffer.sniff_mime(file_bytes, claimed_mime, filename)

		buffers = [file_bytes]
		if self.chunk_size and file_size > self.chunk_size:
			buffers = [file_bytes[i : i + self.chunk_size] for i in range(0, file_size, self.chunk_size)]

		logger.debug("Prep the battlefield – prepared %s buffer(s) for YARA", len(buffers))

		return FilePreprocessContext(
			filename=filename,
			file_size=file_size,
			sha256=sha256,
			mime_result=mime_result,
			buffers=buffers,
			received_at=received_at,
		)

	# ------------------------------------------------------------------
	# Scan entry points
	# ------------------------------------------------------------------

	async def scan_full(self, file_data: bytes, *, filename: Optional[str] = None, claimed_mime: Optional[str] = None) -> Dict[str, Any]:
		context = await self.preprocess_file(file_data, filename=filename, claimed_mime=claimed_mime)
		matches, truncated = await self._execute_scan(context, mode="full")
		return self._build_output(context, matches, mode="full", truncated=truncated)

	async def scan_by_category(
		self,
		file_data: bytes,
		*,
		categories: Optional[Sequence[str]] = None,
		filename: Optional[str] = None,
		claimed_mime: Optional[str] = None,
	) -> Dict[str, Any]:
		context = await self.preprocess_file(file_data, filename=filename, claimed_mime=claimed_mime)
		matches, truncated = await self._execute_scan(context, mode="category", categories=categories)
		return self._build_output(context, matches, mode="category", categories=categories, truncated=truncated)

	async def scan_heuristic(
		self,
		file_data: bytes,
		*,
		filename: Optional[str] = None,
		claimed_mime: Optional[str] = None,
	) -> Dict[str, Any]:
		context = await self.preprocess_file(file_data, filename=filename, claimed_mime=claimed_mime)
		matches, truncated = await self._execute_scan(context, mode="heuristic")
		return self._build_output(context, matches, mode="heuristic", truncated=truncated)

	# ------------------------------------------------------------------
	# Core scan execution
	# ------------------------------------------------------------------

	async def _execute_scan(
		self,
		context: FilePreprocessContext,
		*,
		mode: str,
		categories: Optional[Sequence[str]] = None,
	) -> Tuple[List[MatchRecord], bool]:
		compiled = self._compiled_rules
		if compiled is None:
			raise YaraExecutionError("YARA ruleset is not compiled", code="YARA_RULESET_NOT_READY")

		timeout_seconds: Optional[int] = None
		if self.match_timeout_ms is not None:
			timeout_seconds = int(max(self.match_timeout_ms, 0) / 1000)
		requested_categories = set(_select_categories(categories) or [])
		logger.info("Running %s YARA scan with granular control", mode)

		yara_module = yara
		if yara_module is None:  # pragma: no cover - safety
			raise YaraUnavailableError()

		records: List[MatchRecord] = []
		truncated = False

		try:
			for buffer_slice in context.buffers:
				match_kwargs: Dict[str, Any] = {"data": buffer_slice}
				if timeout_seconds is not None:
					match_kwargs["timeout"] = timeout_seconds
				chunk_matches = compiled.match(**match_kwargs)
				for match in chunk_matches:
					record = self._normalize_match(match)
					if mode == "category" and requested_categories:
						if not self._record_in_categories(record, requested_categories):
							continue
					if mode == "heuristic" and not self._record_is_heuristic(record):
						continue
					records.append(record)
					if len(records) >= self.max_match_records:
						truncated = True
						break
				if truncated:
					break
		except YaraTimeoutErrorType as exc:  # pragma: no cover - runtime behavior
			raise YaraExecutionError("YARA scan timed out", code="YARA_TIMEOUT") from exc
		except YaraErrorType as exc:  # pragma: no cover - runtime behavior
			raise YaraExecutionError(
				f"YARA scan failed: {exc}",
				code="YARA_RUNTIME_ERROR",
			) from exc

		if mode == "heuristic":
			synthetic = self._synthetic_heuristic_matches(context)
			for extra in synthetic:
				if len(records) >= self.max_match_records:
					truncated = True
					break
				records.append(extra)

		logger.debug("We pull out all the receipts – %s matches normalised", len(records))
		return records, truncated

	def _record_in_categories(self, record: MatchRecord, categories: Set[str]) -> bool:
		if not categories:
			return True
		normalized_categories = {_normalize_category_name(category) for category in categories}
		rule_categories = self._rule_categories.get(record.rule_name)
		if rule_categories and rule_categories & normalized_categories:
			return True
		observed: Set[str] = set()
		observed.add(_normalize_category_name(record.namespace))
		observed.update(_normalize_category_name(tag) for tag in record.tags)
		for value in record.metadata.values():
			if isinstance(value, str):
				observed.add(_normalize_category_name(value))
		for category in list(observed):
			observed.update(_expand_category_aliases(category))
		return bool(observed & normalized_categories)

	def _record_is_heuristic(self, record: MatchRecord) -> bool:
		haystack = {tag.lower() for tag in record.tags}
		haystack.update(_normalize_category_name(str(value)) for value in record.metadata.values() if isinstance(value, str))
		return any(keyword in haystack for keyword in HEURISTIC_TAGS)

	def _synthetic_heuristic_matches(self, context: FilePreprocessContext) -> List[MatchRecord]:
		matches: List[MatchRecord] = []
		entropy = self._calculate_entropy(context)
		if entropy >= 7.5:
			matches.append(
				MatchRecord(
					rule_name="Heuristic_HighEntropy",
					namespace="heuristics",
					tags=["entropy", "packed"],
					matched_strings=[MatchString(identifier="$entropy", value=f"entropy={entropy:.2f}", offset=0)],
					metadata={"description": "Derived high entropy heuristic", "provenance": "synthetic"},
					severity="medium",
					family=None,
				)
			)
		if self._mime_suggests_packed(context):
			matches.append(
				MatchRecord(
					rule_name="Heuristic_PackedExecutable",
					namespace="heuristics",
					tags=["packed", "obfuscation"],
					matched_strings=[MatchString(identifier="$packed", value="packed_executable", offset=0)],
					metadata={"description": "Executable indicates packing", "provenance": "synthetic"},
					severity="medium",
					family=None,
				)
			)
		return matches

	def _calculate_entropy(self, context: FilePreprocessContext) -> float:
		data = b"".join(context.buffers)
		if not data:
			return 0.0

		counts = [0] * 256
		for byte in data:
			counts[byte] += 1

		length = len(data)
		if length == 0:
			return 0.0

		import math

		entropy = -sum((count / length) * math.log2(count / length) for count in counts if count)
		return round(entropy, 2)

	def _mime_suggests_packed(self, context: FilePreprocessContext) -> bool:
		mime = context.mime_result.get("detected_mime", "") or ""
		if "pe" not in mime.lower():
			return False
		data = b"".join(context.buffers)
		if len(data) < 1024:
			return False
		# Simple PE header inspection to see if known packer section names exist.
		try:
			if data[:2] != b"MZ":
				return False
			pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
			if pe_offset + 6 > len(data):
				return False
			number_of_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
			optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
			section_table_offset = pe_offset + 24 + optional_header_size
			for index in range(min(number_of_sections, 16)):
				offset = section_table_offset + index * 40
				if offset + 8 > len(data):
					break
				name_bytes = data[offset : offset + 8]
				name = name_bytes.split(b"\x00", 1)[0].decode("ascii", errors="ignore").lower()
				if any(hint in name for hint in PACKER_SECTION_HINTS):
					return True
		except Exception:
			logger.debug("Failed to parse PE headers for packed heuristics", exc_info=True)
		return False

	def _normalize_match(self, match: Any) -> MatchRecord:
		rule_name = getattr(match, "rule", getattr(match, "identifier", ""))
		namespace = getattr(match, "namespace", "unknown") or "unknown"
		tags = tuple(getattr(match, "tags", ()) or ())
		raw_meta = dict(getattr(match, "meta", {}) or {})
		sanitized_meta = _sanitize_metadata(raw_meta)
		strings: List[MatchString] = []
		for item in getattr(match, "strings", ()):
			if len(item) == 3:
				offset, identifier, data = item
			else:
				offset, identifier, data = 0, "unknown", item
			value = _stringify_match_data(data)
			strings.append(
				MatchString(
					identifier=identifier,
					value=_sanitize_string(value),
					offset=int(offset),
				)
			)
		severity = _infer_severity(rule_name, tags)
		family = _infer_family(rule_name, tags)
		return MatchRecord(
			rule_name=rule_name,
			namespace=namespace,
			tags=tags,
			matched_strings=strings,
			metadata=sanitized_meta,
			severity=severity,
			family=family,
		)

	# ------------------------------------------------------------------
	# Output assembly
	# ------------------------------------------------------------------

	def _build_output(
		self,
		context: FilePreprocessContext,
		matches: Sequence[MatchRecord],
		*,
		mode: str,
		categories: Optional[Sequence[str]] = None,
		truncated: bool = False,
	) -> Dict[str, Any]:
		total = len(matches)
		highest = _highest_severity(record.severity for record in matches) if matches else "low"
		next_step = _suggest_next_step(highest)

		matches_payload = [
			{
				"rule_name": record.rule_name,
				"namespace": record.namespace,
				"tags": list(record.tags),
				"severity": record.severity,
				"family": record.family,
				"matched_strings": [
					{"identifier": string.identifier, "value": string.value, "offset": string.offset}
					for string in record.matched_strings
				],
				"metadata": record.metadata,
			}
			for record in matches
		]

		output = {
			"yara_scan_success": True,
			"total_rules_triggered": total,
			"matches": matches_payload,
			"inferred_risk": highest,
			"suggested_next_step": next_step,
			"timestamp": datetime.now(timezone.utc).isoformat(),
			"file": {
				"filename": context.filename,
				"sha256": context.sha256,
				"size": context.file_size,
				"mime": context.mime_result.get("detected_mime"),
			},
			"mode": mode,
			"categories_requested": list(categories or []),
			"provenance": {
				"rule_corpus_last_loaded": self._last_loaded_at.isoformat() if self._last_loaded_at else None,
				"rule_sources": [str(source.path) for source in self._rule_sources],
				"match_cap_hit": truncated,
				"match_cap": self.max_match_records,
			},
		}

		logger.info("This is the holy drop – YARA output handed over to ML engine")
		return output

	# ------------------------------------------------------------------
	# Error response helpers
	# ------------------------------------------------------------------

	def build_error_payload(self, error: YaraServiceError, *, context: Optional[FilePreprocessContext] = None) -> Dict[str, Any]:
		payload = {
			"yara_scan_success": False,
			"error": error.to_dict(),
			"timestamp": datetime.now(timezone.utc).isoformat(),
		}
		if context is not None:
			payload["file"] = {
				"filename": context.filename,
				"sha256": context.sha256,
			}
		return payload

	# ------------------------------------------------------------------
	# Multi-file correlation (optional)
	# ------------------------------------------------------------------

	@staticmethod
	def correlate_results(results: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
		"""Identify cross-file indicators for the case footprint."""

		if not results:
			return {"shared_iocs": [], "families": []}

		shared_strings: Dict[Tuple[str, str], int] = {}
		family_hits: Dict[str, int] = {}

		for result in results:
			for match in result.get("matches", []):
				for string in match.get("matched_strings", []):
					key = (match.get("rule_name"), string.get("value"))
					shared_strings[key] = shared_strings.get(key, 0) + 1
				family = match.get("family")
				if family:
					family_hits[family] = family_hits.get(family, 0) + 1

		shared = [
			{"rule_name": key[0], "value": key[1], "occurrences": count}
			for key, count in shared_strings.items()
			if count > 1
		]
		families = [
			{"family": family, "occurrences": count}
			for family, count in family_hits.items()
			if count > 1
		]

		return {"shared_iocs": shared, "families": families}


__all__ = [
	"YaraScanService",
	"YaraServiceError",
	"YaraCompilationError",
	"YaraExecutionError",
	"YaraUnavailableError",
]


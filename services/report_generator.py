from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence, Tuple


class _ReportBuilder:
	"""Utility to keep the final report within a strict line budget."""

	def __init__(self, max_lines: int, max_line_length: int = 200) -> None:
		self.max_lines = max(1, max_lines)
		self.max_line_length = max(40, max_line_length)
		self.lines: List[str] = []
		self.truncated = False

	def add_section(self, title: str, entries: Sequence[str]) -> None:
		sanitized_entries = [entry for entry in entries if entry]
		if not sanitized_entries:
			return
		if not self._append_line(f"[{title}]"):
			return
		for entry in sanitized_entries:
			if not self._append_line(entry):
				break

	def _append_line(self, text: str) -> bool:
		if len(self.lines) >= self.max_lines:
			self.truncated = True
			return False
		cleaned = self._sanitize(text)
		if not cleaned:
			return True
		self.lines.append(cleaned)
		return True

	def _sanitize(self, text: str) -> str:
		collapsed = " ".join(str(text).strip().split())
		if not collapsed:
			return ""
		if len(collapsed) > self.max_line_length:
			return collapsed[: self.max_line_length - 3] + "..."
		return collapsed

	def render(self) -> str:
		if not self.lines:
			return "no_report_data"
		final_lines = list(self.lines)
		if self.truncated and final_lines:
			final_lines[-1] = self._sanitize("... trimmed to stay within line budget ...")
		return "\n".join(final_lines)


class ReportGeneratorService:
	"""Aggregate critical signals from all scanners into a concise report."""

	DEFAULT_MAX_LINES = 100
	MIME_REASON_LIMIT = 160

	def __init__(self, *, max_lines: int = DEFAULT_MAX_LINES) -> None:
		self.max_lines = max(1, min(max_lines, self.DEFAULT_MAX_LINES))

	async def generate_report(self, evidence_result: Dict[str, Any]) -> str:
		payload = evidence_result or {}
		hash_lookup = self._parse_hash_lookup(payload.get("hash_lookup"))
		mime_result = self._ensure_dict(payload.get("mime_type"))
		entropy_result = self._ensure_dict(payload.get("entropy"))
		clam_result = self._normalize_clamav(payload.get("clam_av"))
		yara_result = self._normalize_yara(payload.get("yara_scan"))
		file_type_analysis = self._ensure_dict(payload.get("file_type_analysis"))
		file_category = self._determine_file_category(payload, mime_result, file_type_analysis)

		risk_level, risk_reasons = self._derive_risk_level(
			mime_result, entropy_result, clam_result, yara_result
		)

		builder = _ReportBuilder(max_lines=self.max_lines)
		builder.add_section(
			"Evidence",
			self._build_evidence_lines(payload, risk_level, risk_reasons, file_category),
		)
		builder.add_section("Hashing", self._build_hash_lines(payload, hash_lookup))
		builder.add_section("MIME", self._build_mime_lines(mime_result))
		builder.add_section("Entropy", self._build_entropy_lines(entropy_result))
		builder.add_section("ClamAV", self._build_clamav_lines(clam_result))
		builder.add_section("YARA", self._build_yara_lines(yara_result))
		builder.add_section(
			"FileType",
			self._build_file_type_lines(file_type_analysis, file_category),
		)
		builder.add_section("Processing", self._build_processing_lines(payload))

		return builder.render()

	# ------------------------------------------------------------------
	# Section builders
	# ------------------------------------------------------------------

	def _build_evidence_lines(
		self,
		payload: Dict[str, Any],
		risk_level: str,
		risk_reasons: Sequence[str],
		file_category: Optional[str],
	) -> List[str]:
		lines: List[str] = []
		complaint_id = payload.get("complaint_id")
		evidence_id = payload.get("evidence_id")
		status = payload.get("status")
		file_name = payload.get("file_name")
		extension = payload.get("file_name_extension")

		if complaint_id:
			lines.append(f"complaint_id: {complaint_id}")
		if evidence_id:
			lines.append(f"evidence_id: {evidence_id}")
		if file_name:
			name_line = f"file: {file_name}"
			if extension:
				name_line += f" ({extension})"
			lines.append(name_line)
		if file_category:
			lines.append(f"category: {file_category}")
		if status:
			lines.append(f"status: {status}")

		lines.append(f"risk_level: {risk_level}")
		if risk_reasons:
			reason_text = "; ".join(risk_reasons[:3])
			lines.append(f"risk_drivers: {self._truncate_text(reason_text, 180)}")

		return lines

	def _build_hash_lines(self, payload: Dict[str, Any], lookup: Dict[str, Any]) -> List[str]:
		lines: List[str] = []
		file_hash = payload.get("hash")
		if file_hash:
			lines.append(f"sha256: {file_hash}")

		if lookup:
			local_hit = self._format_bool(lookup.get("local_lookup"))
			online_hit = self._format_bool(lookup.get("online_lookup"))
			lines.append(f"hash_lookup: local={local_hit} | online={online_hit}")

		return lines

	def _build_mime_lines(self, mime_result: Dict[str, Any]) -> List[str]:
		if not mime_result:
			return []

		detected = mime_result.get("detected_mime") or mime_result.get("mime") or "unknown"
		claimed = mime_result.get("claimed_mime") or "unknown"
		category = mime_result.get("category") or "unknown"
		confidence = mime_result.get("confidence")
		action = mime_result.get("action") or "unknown"
		suspicious = self._format_bool(mime_result.get("suspicious"))
		mime_match = self._format_bool(mime_result.get("mime_match"))
		extension_match = self._format_bool(mime_result.get("extension_match"))
		file_size = mime_result.get("file_size")

		lines = [
			f"detected={detected} | claimed={claimed} | category={category}",
			f"confidence={self._format_float(confidence)} | action={action} | suspicious={suspicious}",
			f"mime_match={mime_match} | extension_match={extension_match}",
		]

		if file_size:
			lines.append(f"file_size_bytes={file_size}")

		reason = mime_result.get("reason") or mime_result.get("magic_byte_summary")
		if reason:
			lines.append(f"reason: {self._truncate_text(reason, self.MIME_REASON_LIMIT)}")

		return lines

	def _build_entropy_lines(self, entropy_result: Dict[str, Any]) -> List[str]:
		entropy_block = self._ensure_dict(entropy_result.get("entropy"))
		archive_block = self._ensure_dict(entropy_result.get("archive"))
		decoded_block = self._ensure_dict(entropy_result.get("decoded_streams"))

		if not entropy_block and not archive_block and not decoded_block:
			return []

		lines: List[str] = []
		if entropy_block:
			lines.append(
				" | ".join(
					[
						f"whole={self._format_float(entropy_block.get('whole_file'))}",
						f"max={self._format_float(entropy_block.get('max'))}",
						f"compressibility={self._format_float(entropy_block.get('compressibility_ratio'))}",
						f"chi2={self._format_float(entropy_block.get('chi2'))}",
					]
				)
			)

			top_windows = entropy_block.get("top_windows") or []
			if top_windows:
				top = top_windows[0]
				offset = top.get("offset")
				entropy_val = self._format_float(top.get("entropy"))
				lines.append(f"top_window: offset={offset} | entropy={entropy_val}")

		if archive_block:
			lines.append(
				"archive: "
				+ " | ".join(
					[
						f"is_archive={self._format_bool(archive_block.get('is_archive'))}",
						f"entries={archive_block.get('entry_count', 0)}",
						f"top_entry_entropy={self._format_float(archive_block.get('top_entry_entropy'))}",
					]
				)
			)

		if decoded_block:
			lines.append(f"decoded_streams: {decoded_block.get('count', 0)}")

		return lines

	def _build_clamav_lines(self, clam_result: Dict[str, Any]) -> List[str]:
		if not clam_result:
			return []

		status = clam_result.get("status") or "unknown"
		infected = self._format_bool(clam_result.get("infected"))
		threat = clam_result.get("threat_name") or "none"
		threat_count = clam_result.get("threat_count", 0)
		signature_family = clam_result.get("signature_family") or "unknown"
		lines = [
			f"status={status} | infected={infected} | threat={threat} ({threat_count})",
			f"heuristic={self._format_bool(clam_result.get('is_heuristic'))} | pua={self._format_bool(clam_result.get('is_pua'))} | family={signature_family}",
		]

		scan_duration = clam_result.get("scan_duration_ms")
		engine_version = clam_result.get("engine_version") or "unknown"
		db_age = clam_result.get("db_age_days")
		if scan_duration or engine_version or db_age is not None:
			lines.append(
				"engine="
				+ " | ".join(
					filter(
						None,
						[
							f"version={engine_version}" if engine_version else None,
							f"db_age_days={db_age}" if db_age is not None else None,
							f"duration_ms={scan_duration}" if scan_duration is not None else None,
						],
					)
				)
			)

		return lines

	def _build_yara_lines(self, yara_result: Dict[str, Any]) -> List[str]:
		if not yara_result:
			return []

		total = yara_result.get("total_rules_triggered", 0)
		density = self._format_float(yara_result.get("match_density_per_mb"))
		truncated = self._format_bool(yara_result.get("match_cap_hit"))
		matched_strings = yara_result.get("matched_strings_total", 0)

		lines = [
			f"rules_triggered={total} | density_per_mb={density} | matched_strings={matched_strings} | truncated={truncated}",
		]

		severity_counts = yara_result.get("severity_counts", {})
		if isinstance(severity_counts, dict):
			non_zero = [f"{k}={v}" for k, v in severity_counts.items() if v]
			if non_zero:
				lines.append("severity: " + " | ".join(non_zero))

		top_matches = yara_result.get("top_matches") or []
		if top_matches:
			rendered = []
			for match in top_matches[:3]:
				rule = match.get("rule_name") or "rule"
				severity = match.get("severity") or "unknown"
				score = self._format_float(match.get("match_score"))
				rendered.append(f"{rule}({severity},{score})")
			lines.append("top_matches: " + "; ".join(rendered))

		top_tags = yara_result.get("top_tags") or []
		if top_tags:
			rendered_tags = []
			for entry in top_tags[:3]:
				tag = entry.get("tag") or "tag"
				count = entry.get("count", 0)
				rendered_tags.append(f"{tag}({count})")
			lines.append("top_tags: " + ", ".join(rendered_tags))

		return lines

	def _build_file_type_lines(
		self,
		analysis: Dict[str, Any],
		file_category: Optional[str],
	) -> List[str]:
		if not analysis:
			return []

		lines: List[str] = []

		verdict = analysis.get("verdict")
		if verdict:
			lines.append(f"verdict: {verdict}")

		metadata_fields = [
			"document_title",
			"author",
			"page_count",
			"language",
			"camera_make",
			"camera_model",
			"capture_time",
			"dimensions",
			"duration",
			"codec",
			"package_name",
			"version_name",
			"signing_issuer",
		]
		structure_fields = [
			"char_count",
			"page_count",
			"duration_seconds",
			"frame_rate",
			"width",
			"height",
			"channels",
		]
		indicator_fields = ["urls", "domains", "ips", "emails", "file_hashes"]

		metadata_line = self._summarize_section(
			analysis.get("metadata"), metadata_fields, label="metadata"
		)
		if metadata_line:
			lines.append(metadata_line)

		structure_line = self._summarize_section(
			analysis.get("structure"), structure_fields, label="structure"
		)
		if structure_line:
			lines.append(structure_line)

		entities = analysis.get("entities")
		if isinstance(entities, dict):
			named_entities = entities.get("named_entities")
			pii_summary = entities.get("pii_summary")
			if isinstance(named_entities, list) or isinstance(pii_summary, dict):
				counts = []
				if isinstance(named_entities, list):
					counts.append(f"entities={len(named_entities)}")
				if isinstance(pii_summary, dict):
					pii_counts = [
						f"{key}={len(value)}"
						for key, value in pii_summary.items()
						if isinstance(value, list) and value
					]
					if pii_counts:
						counts.append("pii:" + ",".join(pii_counts))
				if counts:
					lines.append("entities: " + " | ".join(counts))

		indicator_line = self._summarize_section(
			analysis.get("indicators"), indicator_fields, label="indicators"
		)
		if indicator_line:
			lines.append(indicator_line)

		nlp_block = analysis.get("nlp")
		if isinstance(nlp_block, dict):
			summary = nlp_block.get("summary")
			language = nlp_block.get("language")
			if summary or language:
				snippet = self._truncate_text(summary, 120) if summary else None
				parts = [f"lang={language}" if language else None]
				if snippet:
					parts.append(f"summary={snippet}")
				lines.append("nlp: " + " | ".join(part for part in parts if part))

		confidence_block = self._ensure_dict(analysis.get("confidence"))
		overall_conf = confidence_block.get("overall_confidence")
		if overall_conf is not None:
			lines.append(f"confidence: overall={self._format_float(overall_conf)}")

		numeric_features = (
			self._ensure_dict(analysis.get("feature_vector")).get("numeric_features")
		)
		numeric_line = self._summarize_numeric_features(numeric_features)
		if numeric_line:
			lines.append(numeric_line)

		if not lines and file_category:
			lines.append(f"no structured summary for category {file_category}")

		return lines

	def _build_processing_lines(self, payload: Dict[str, Any]) -> List[str]:
		lines: List[str] = []
		message = payload.get("message")
		error = payload.get("error")

		if message:
			lines.append(f"message: {self._truncate_text(message, 160)}")
		if error:
			lines.append(f"error: {self._truncate_text(error, 160)}")

		return lines

	# ------------------------------------------------------------------
	# Helpers
	# ------------------------------------------------------------------

	def _ensure_dict(self, value: Any) -> Dict[str, Any]:
		return value if isinstance(value, dict) else {}

	def _parse_hash_lookup(self, value: Any) -> Dict[str, Any]:
		if isinstance(value, dict):
			return value
		if isinstance(value, str):
			try:
				parsed = json.loads(value)
				return parsed if isinstance(parsed, dict) else {}
			except json.JSONDecodeError:
				return {}
		return {}

	def _normalize_clamav(self, value: Any) -> Dict[str, Any]:
		if isinstance(value, dict):
			if "clamav" in value and isinstance(value.get("clamav"), dict):
				return value["clamav"]
			return value
		return {}

	def _normalize_yara(self, value: Any) -> Dict[str, Any]:
		if isinstance(value, dict):
			if "yara" in value and isinstance(value.get("yara"), dict):
				return value["yara"]
			return value
		return {}

	def _determine_file_category(
		self,
		payload: Dict[str, Any],
		mime_result: Dict[str, Any],
		analysis: Dict[str, Any],
	) -> Optional[str]:
		return (
			mime_result.get("category")
			or analysis.get("category")
			or payload.get("file_category")
		)

	def _derive_risk_level(
		self,
		mime_result: Dict[str, Any],
		entropy_result: Dict[str, Any],
		clam_result: Dict[str, Any],
		yara_result: Dict[str, Any],
	) -> Tuple[str, List[str]]:
		score = 0
		reasons: List[str] = []

		if clam_result.get("status") == "infected":
			score += 4
			reasons.append("ClamAV detected malware")

		yara_hits = yara_result.get("total_rules_triggered", 0)
		if yara_hits:
			increment = 2 if yara_hits >= 5 else 1
			score += increment
			reasons.append(f"{yara_hits} YARA rules triggered")

		if mime_result.get("suspicious") or (
			mime_result.get("action") in {"quarantine", "reject"}
		):
			score += 1
			reasons.append("MIME classifier flagged mismatch")

		entropy_block = self._ensure_dict(entropy_result.get("entropy"))
		whole_entropy = entropy_block.get("whole_file")
		if isinstance(whole_entropy, (int, float)) and whole_entropy >= 7.5:
			score += 1
			reasons.append(f"High entropy ({whole_entropy})")

		if score >= 4:
			level = "high"
		elif score >= 2:
			level = "medium"
		else:
			level = "low"

		# Deduplicate reasons while preserving order
		seen = set()
		deduped: List[str] = []
		for reason in reasons:
			if reason not in seen:
				deduped.append(reason)
				seen.add(reason)

		return level, deduped

	def _truncate_text(self, text: Optional[str], limit: int) -> str:
		if not text:
			return ""
		collapsed = " ".join(text.split())
		if len(collapsed) > limit:
			return collapsed[: limit - 3] + "..."
		return collapsed

	def _format_bool(self, value: Any) -> str:
		return "true" if bool(value) else "false"

	def _format_float(self, value: Any) -> str:
		if isinstance(value, (int, float)):
			return f"{float(value):.3f}".rstrip("0").rstrip(".")
		return "n/a"

	def _summarize_section(
		self,
		section: Any,
		field_order: Sequence[str],
		*,
		label: str,
		max_fields: int = 3,
	) -> Optional[str]:
		if not isinstance(section, dict):
			return None

		values: List[str] = []
		for field in field_order:
			if field not in section:
				continue
			formatted = self._format_scalar(section.get(field))
			if formatted is None:
				continue
			values.append(f"{field}={formatted}")
			if len(values) >= max_fields:
				break

		if not values:
			return None

		return f"{label}: " + " | ".join(values)

	def _format_scalar(self, value: Any) -> Optional[str]:
		if value is None:
			return None
		if isinstance(value, bool):
			return self._format_bool(value)
		if isinstance(value, (int, float)):
			return self._format_float(value)
		if isinstance(value, str):
			cleaned = self._truncate_text(value, 80)
			return cleaned or None
		if isinstance(value, list):
			return str(len(value))
		if isinstance(value, dict):
			return f"{len(value)} keys"
		return None

	def _summarize_numeric_features(self, section: Any) -> Optional[str]:
		if not isinstance(section, dict):
			return None
		interesting_keys = [
			"word_count",
			"unique_urls",
			"suspicious_url_count",
			"pii_count",
			"yara_count",
			"avg_entropy",
		]
		values = []
		for key in interesting_keys:
			if key not in section:
				continue
			formatted = self._format_scalar(section.get(key))
			if formatted is None:
				continue
			values.append(f"{key}={formatted}")
		if not values:
			return None
		return "features: " + " | ".join(values)


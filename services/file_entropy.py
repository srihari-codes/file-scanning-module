import asyncio
import base64
import binascii
import io
import math
import statistics
import time
import zipfile
import tarfile
import re
import zlib
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union, IO

from utils.logger import get_logger

BytesLike = Union[bytes, bytearray, memoryview]
logger = get_logger(__name__)


class FileEntropyService:
    """Enhanced FileEntropyService with multi-metric decisioning to reduce false
    positives/negatives. Key upgrades:
      - Combined metrics: Shannon entropy, compressibility (zlib), chi-squared
        distribution test, and sliding-window maxima.
      - Adaptive thresholds per MIME category.
      - Faster/robust base64 and uuencode detection.
      - Optional calibration helper (collect labeled samples to fit weights).

    Note: to reach FP/FN <5% in a real product, you must calibrate weights and
    thresholds against representative labeled datasets (benign + packed/malware).
    """

    def __init__(
        self,
        *,
        chunk_size: int = 4096,
        stride: Optional[int] = None,
        top_n_windows: int = 5,
        threshold_high: float = 7.6,
        threshold_suspect: float = 6.6,
        memory_limit_mb: int = 256,
        base64_scan_limit_mb: int = 8,
        archive_analysis_max_mb: int = 32,
        time_budget_small: float = 1.0,
        time_budget_medium: float = 5.0,
        time_budget_large: float = 10.0,
        # new hyperparameters
        compressibility_threshold: float = 0.65,
        chi2_threshold: float = 150.0,
        detection_score_threshold: float = 0.7,
        detection_weights: Optional[Dict[str, float]] = None,
    ) -> None:
        self.chunk_size = max(64, chunk_size)
        self.stride = stride if stride and stride > 0 else self.chunk_size // 2
        self.top_n_windows = max(1, top_n_windows)
        self.threshold_high = threshold_high
        self.threshold_suspect = threshold_suspect
        self.memory_limit = memory_limit_mb * 1024 * 1024
        self.base64_scan_limit = base64_scan_limit_mb * 1024 * 1024
        self.archive_analysis_max_bytes = archive_analysis_max_mb * 1024 * 1024
        self.time_budget_small = time_budget_small
        self.time_budget_medium = time_budget_medium
        self.time_budget_large = time_budget_large

        # New detection hyperparams
        self.compressibility_threshold = compressibility_threshold
        self.chi2_threshold = chi2_threshold
        self.detection_score_threshold = detection_score_threshold
        self.detection_weights = (
            detection_weights
            if detection_weights is not None
            else {
                "entropy": 0.45,
                "compressibility": 0.35,
                "chi2": 0.15,
                "packer_hint": 0.05,
            }
        )

        # improved base64 capture: anchored groups of 32+ base64 chars with optional padding
        self._base64_regex = re.compile(rb"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])")
        self._uuencode_header_regex = re.compile(rb"^begin [0-7]{3} .+$", re.MULTILINE)

        self._metrics = {
            "entropy_jobs_total": 0,
            "entropy_timeouts_total": 0,
            "suspected_packed_count": 0,
            "latency_sum_ms": 0.0,
        }

    async def calculate_entropy(
        self,
        file_data: Union[BytesLike, io.BufferedReader, io.BytesIO],
        mime_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._calculate_entropy_sync, file_data, mime_info)

    def _calculate_entropy_sync(
        self,
        file_data: Union[BytesLike, io.BufferedReader, io.BytesIO],
        mime_info: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        start_time = time.perf_counter()
        data_view, data_len, partial, partial_reason = self._normalize_input(file_data)
        notes: List[str] = []

        logger.debug("Starting entropy analysis; size=%d bytes", data_len)

        if data_len == 0:
            result = self._empty_result()
            return result

        # whole-file entropy
        whole_entropy = self._round_entropy(self._shannon_entropy(data_view))

        # sliding windows
        windows, window_stats, time_exceeded = self._compute_sliding_windows(data_view, start_time, data_len)
        if time_exceeded:
            partial = True
            partial_reason = "timeout"
            logger.warning("Entropy sliding window timeout after %.2f ms", (time.perf_counter() - start_time) * 1000)

        # additional metrics
        compress_ratio = self._compressibility_score(data_view)
        chi2 = self._chi_squared_stat(data_view)

        # archive and decoding analysis
        archive_entries, embedded_indexes = self._analyze_archives(data_view, data_len, mime_info, partial, notes)
        decoded_streams = self._analyze_decoded_streams(data_view, data_len, notes)

        # Build simplified result
        result: Dict[str, Any] = {
            "entropy": {
                "method": "shannon",
                "whole_file": whole_entropy,
                "mean": self._round_entropy(window_stats["mean"]),
                "median": self._round_entropy(window_stats["median"]),
                "max": self._round_entropy(window_stats["max"]),
                "stddev": self._round_entropy(window_stats["stddev"]),
                "percentiles": {k: self._round_entropy(v) for k, v in window_stats["percentiles"].items()},
                "chunk_size": window_stats["chunk_size"],
                "stride": window_stats["stride"],
                "window_count": window_stats["window_count"],
                "compressibility_ratio": round(compress_ratio, 4),
                "chi2": round(chi2, 3),
                "top_windows": [
                    {
                        "offset": top["offset"],
                        "length": top["length"],
                        "entropy": self._round_entropy(top["entropy"]),
                    }
                    for top in window_stats["top_windows"]
                ],
            },
            "archive": {
                "is_archive": len(archive_entries) > 0,
                "entry_count": len(archive_entries),
                "top_entry_entropy": max((e["entropy"] for e in archive_entries), default=None) if archive_entries else None,
                "entries_sample": archive_entries[:5] if archive_entries else [],  # First 5 entries only
            },
            "decoded_streams": {
                "count": len(decoded_streams),
                "sample": decoded_streams[:3] if decoded_streams else [],  # First 3 streams only
            },
        }

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        logger.debug(
            "Entropy analysis complete; size=%d bytes, whole_entropy=%.3f, latency=%.2f ms",
            data_len,
            whole_entropy,
            latency_ms,
        )

        return result

    def _normalize_input(
        self,
        file_data: Union[BytesLike, io.BufferedReader, io.BytesIO],
    ) -> Tuple[memoryview, int, bool, Optional[str]]:
        partial = False
        partial_reason: Optional[str] = None

        if isinstance(file_data, memoryview):
            data_view = file_data.cast("B")
        elif isinstance(file_data, (bytes, bytearray)):
            data_view = memoryview(file_data).cast("B")
        elif hasattr(file_data, "read"):
            buffer = bytearray()
            remaining = self.memory_limit
            while remaining > 0:
                chunk = file_data.read(min(remaining, 4 * 1024 * 1024))
                if not chunk:
                    break
                buffer.extend(chunk)
                remaining -= len(chunk)
            extra = file_data.read(1)
            if extra:
                partial = True
                partial_reason = "memory_limit_exceeded"
                logger.warning("Input truncated at memory limit (%d bytes).", self.memory_limit)
            data_view = memoryview(buffer).cast("B")
        else:
            raise TypeError("Unsupported input type for entropy analysis.")

        data_len = len(data_view)
        if data_len > self.memory_limit:
            data_view = data_view[: self.memory_limit]
            data_len = len(data_view)
            partial = True
            partial_reason = "memory_limit_exceeded"
            logger.warning("Input sliced to memory cap (%d bytes).", self.memory_limit)

        return data_view, data_len, partial, partial_reason

    def _compute_sliding_windows(
        self,
        data_view: memoryview,
        start_time: float,
        data_len: int,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any], bool]:
        chunk_size = min(self.chunk_size, data_len)
        stride = max(1, self.stride)
        window_entropies: List[float] = []
        windows: List[Dict[str, Any]] = []
        offset = 0
        time_exceeded = False
        percentiles = {"p25": 0.0, "p50": 0.0, "p75": 0.0, "p90": 0.0}

        time_budget = self._select_time_budget(data_len)

        # sample every Nth window if file is huge to keep accuracy + speed
        max_windows = max(1, min(2000, (data_len // chunk_size) + 1))
        sampled = 0

        while offset < data_len:
            end = min(offset + chunk_size, data_len)
            window = data_view[offset:end]
            entropy = self._shannon_entropy(window)
            windows.append({"offset": offset, "length": end - offset, "entropy": entropy})
            window_entropies.append(entropy)

            if end == data_len:
                break
            offset += stride
            sampled += 1
            if sampled >= max_windows:
                break

            if (time.perf_counter() - start_time) > time_budget:
                time_exceeded = True
                break

        if not windows:
            windows.append({"offset": 0, "length": data_len, "entropy": 0.0})
            window_entropies.append(0.0)

        mean_val = sum(window_entropies) / len(window_entropies)
        median_val = statistics.median(window_entropies)
        stddev_val = statistics.pstdev(window_entropies) if len(window_entropies) > 1 else 0.0
        max_val = max(window_entropies)

        if window_entropies:
            percentiles = {
                "p25": self._percentile(window_entropies, 25),
                "p50": self._percentile(window_entropies, 50),
                "p75": self._percentile(window_entropies, 75),
                "p90": self._percentile(window_entropies, 90),
            }

        top_windows = sorted(
            windows,
            key=lambda entry: (-entry["entropy"], entry["offset"]),
        )[: self.top_n_windows]

        stats = {
            "mean": mean_val,
            "median": median_val,
            "max": max_val,
            "stddev": stddev_val,
            "percentiles": percentiles,
            "chunk_size": chunk_size,
            "stride": stride,
            "window_count": len(window_entropies),
            "top_windows": top_windows,
        }
        return windows, stats, time_exceeded

    def _analyze_archives(
        self,
        data_view: memoryview,
        data_len: int,
        mime_info: Optional[Dict[str, Any]],
        partial: bool,
        notes: List[str],
    ) -> Tuple[List[Dict[str, Any]], List[int]]:
        if partial:
            return [], []

        if data_len > self.archive_analysis_max_bytes:
            notes.append(
                f"Archive analysis skipped (size {data_len} > {self.archive_analysis_max_bytes} bytes)."
            )
            logger.info("Skipping archive analysis for oversized input (%d bytes).", data_len)
            return [], []

        archive_entries: List[Dict[str, Any]] = []
        embedded_indexes: List[int] = []

        mime_type = (mime_info or {}).get("mime") if mime_info else None
        category = (mime_info or {}).get("category") if mime_info else None

        if not self._should_attempt_archive(mime_type, category, data_view):
            return [], []

        backing = data_view.obj
        if isinstance(backing, (bytes, bytearray)):
            raw_stream = io.BytesIO(backing)
        else:
            raw_stream = io.BytesIO(data_view.tobytes())

        raw_stream.seek(0)
        try:
            with zipfile.ZipFile(raw_stream) as zf:
                for idx, info in enumerate(zf.infolist()):
                    length = info.file_size
                    if length == 0:
                        entropy_val = 0.0
                    else:
                        with zf.open(info) as entry_fp:
                            entropy_val = self._compute_stream_entropy(entry_fp, length)
                    archive_entry = {
                        "name": info.filename,
                        "offset": getattr(info, "header_offset", 0),
                        "length": length,
                        "entropy": self._round_entropy(entropy_val),
                    }
                    archive_entries.append(archive_entry)
                    if entropy_val > self.threshold_high:
                        embedded_indexes.append(idx)
                return archive_entries, embedded_indexes
        except (zipfile.BadZipFile, RuntimeError):
            raw_stream.seek(0)

        try:
            with tarfile.open(fileobj=raw_stream) as tf:
                for idx, member in enumerate(tf.getmembers()):
                    if not member.isfile():
                        continue
                    length = member.size
                    if length == 0:
                        entropy_val = 0.0
                    else:
                        extracted = tf.extractfile(member)
                        if extracted is None:
                            continue
                        entropy_val = self._compute_stream_entropy(extracted, length)
                    archive_entry = {
                        "name": member.name,
                        "offset": idx,
                        "length": length,
                        "entropy": self._round_entropy(entropy_val),
                    }
                    archive_entries.append(archive_entry)
                    if entropy_val > self.threshold_high:
                        embedded_indexes.append(idx)
                return archive_entries, embedded_indexes
        except (tarfile.ReadError, RuntimeError):
            pass

        return archive_entries, embedded_indexes

    def _analyze_decoded_streams(
        self,
        data_view: memoryview,
        data_len: int,
        notes: List[str],
    ) -> List[Dict[str, Any]]:
        decoded_streams: List[Dict[str, Any]] = []
        if data_len > self.base64_scan_limit:
            notes.append(
                f"Skipped encoded stream detection (size {data_len} exceeds base64 scan limit {self.base64_scan_limit})."
            )
            return decoded_streams

        raw_bytes = data_view.tobytes()
        if not self._is_mostly_text(raw_bytes, threshold=0.5):
            notes.append("Skipped encoded stream detection due to non-textual content.")
            return decoded_streams

        for match in self._base64_regex.finditer(raw_bytes):
            candidate = match.group(1)
            offset = match.start(1)
            try:
                decoded = base64.b64decode(candidate, validate=True)
            except (binascii.Error, ValueError):
                continue
            if len(decoded) < 32:
                continue
            entropy_val = self._round_entropy(self._shannon_entropy(decoded))
            decoded_streams.append(
                {
                    "method": "base64",
                    "offset": offset,
                    "length": len(decoded),
                    "entropy": entropy_val,
                }
            )

        for match in self._uuencode_header_regex.finditer(raw_bytes):
            uu_offset = match.start()
            block = self._extract_uu_block(raw_bytes, uu_offset)
            if block is None:
                continue
            decoded = self._decode_uu_block(block)
            if not decoded:
                notes.append("Detected uuencode header but decoding failed.")
                continue
            entropy_val = self._round_entropy(self._shannon_entropy(decoded))
            decoded_streams.append(
                {
                    "method": "uuencode",
                    "offset": uu_offset,
                    "length": len(decoded),
                    "entropy": entropy_val,
                }
            )

        return decoded_streams

    def _detect_packers(self, data_view: memoryview) -> List[str]:
        hints: List[str] = []
        raw_bytes = data_view.tobytes()

        if b"UPX!" in raw_bytes:
            hints.append("UPX")

        if len(raw_bytes) >= 0x40 and raw_bytes.startswith(b"MZ"):
            pe_offset_bytes = raw_bytes[0x3C:0x40]
            if len(pe_offset_bytes) == 4:
                pe_offset = int.from_bytes(pe_offset_bytes, "little", signed=False)
                if 0 < pe_offset <= len(raw_bytes) - 4 and raw_bytes[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                    if pe_offset + 24 <= len(raw_bytes):
                        size_of_optional = int.from_bytes(
                            raw_bytes[pe_offset + 20 : pe_offset + 22], "little"
                        )
                        number_of_sections = int.from_bytes(
                            raw_bytes[pe_offset + 6 : pe_offset + 8], "little"
                        )
                        section_table_offset = pe_offset + 24 + size_of_optional
                        if section_table_offset <= len(raw_bytes):
                            last_section_end = 0
                            for i in range(number_of_sections):
                                entry_offset = section_table_offset + i * 40
                                if entry_offset + 40 > len(raw_bytes):
                                    break
                                raw_size = int.from_bytes(
                                    raw_bytes[entry_offset + 16 : entry_offset + 20], "little"
                                )
                                raw_pointer = int.from_bytes(
                                    raw_bytes[entry_offset + 20 : entry_offset + 24], "little"
                                )
                                last_section_end = max(last_section_end, raw_pointer + raw_size)
                            overlay = len(raw_bytes) - last_section_end if last_section_end else 0
                            if overlay > 256 * 1024:
                                hints.append("potential_overlay")
        return hints

    def _get_adaptive_thresholds(self, mime_info: Optional[Dict[str, Any]]) -> Tuple[float, float]:
        """Return adaptive thresholds based on MIME type to reduce false positives."""
        if not mime_info:
            return self.threshold_high, self.threshold_suspect
        
        mime_type = mime_info.get("mime", "").lower()
        category = mime_info.get("category", "").lower()
        
        # Legitimately high-entropy formats - raise thresholds significantly
        if category in {"image", "video", "audio", "archive"}:
            return 7.95, 7.8  # Very high thresholds for multimedia/archives
        
        if category == "document":
            # Modern docs (DOCX, PPTX, PDF) are compressed - moderately high threshold
            return 7.9, 7.7
        
        if "image" in mime_type or "video" in mime_type or "audio" in mime_type:
            return 7.95, 7.8
        
        if "zip" in mime_type or "compressed" in mime_type or "archive" in mime_type:
            return 7.95, 7.8
        
        if "pdf" in mime_type or "officedocument" in mime_type:
            return 7.9, 7.7
        
        # Text/script files - keep original strict thresholds
        if category in {"text", "code", "script"}:
            return 7.5, 6.5
        
        # Executables - strict thresholds
        if category == "executable" or "executable" in mime_type:
            return 7.6, 6.6
        
        # Default
        return self.threshold_high, self.threshold_suspect

    def _build_decision_from_score(
        self,
        whole_entropy: float,
        window_stats: Dict[str, Any],
        detection_score: float,
        norm_entropy: float,
        compress_ratio: float,
        chi2: float,
        packer_hints: List[str],
        mime_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Decision combines classical heuristics with detection_score to be more robust."""
        # Get adaptive thresholds based on file type
        threshold_high, threshold_suspect = self._get_adaptive_thresholds(mime_info)
        
        suspected_packed = detection_score >= self.detection_score_threshold or whole_entropy > threshold_high or window_stats["max"] > threshold_high
        suspicious_entropy = threshold_suspect <= whole_entropy <= threshold_high
        localized_high_entropy = window_stats["max"] > threshold_high

        route_candidates: List[str] = []
        explanation_parts: List[str] = []

        # prefer data-driven score as primary signal
        if detection_score >= self.detection_score_threshold:
            route_candidates.extend(["unpack_attempt", "sandbox_immediate"])
            explanation_parts.append(f"detection_score={detection_score:.3f} >= {self.detection_score_threshold}")
        
        # Add context about adaptive thresholds
        mime_type = mime_info.get("mime", "unknown") if mime_info else "unknown"
        category = mime_info.get("category", "unknown") if mime_info else "unknown"

        if localized_high_entropy:
            route_candidates.append("extract_embedded_windows")
            explanation_parts.append("localized_high_entropy detected")

        if suspicious_entropy and not suspected_packed:
            explanation_parts.append("whole_file within suspect range")

        if packer_hints:
            route_candidates.append("packer_signature_detected")
            explanation_parts.append("packer signatures found: " + ",".join(packer_hints))

        canonical_order = [
            "unpack_attempt",
            "packer_signature_detected",
            "inspect_archive_entries",
            "sandbox_immediate",
            "extract_embedded_windows",
        ]
        route_set = set(route_candidates)
        ordered_route = [route for route in canonical_order if route in route_set]
        for extra in sorted(route_set - set(ordered_route)):
            ordered_route.append(extra)

        priority = "low"
        if suspected_packed:
            priority = "high"
        elif suspicious_entropy or localized_high_entropy:
            priority = "medium"

        decision = {
            "suspected_packed": bool(suspected_packed),
            "suspicious_entropy": bool(suspicious_entropy),
            "localized_high_entropy": bool(localized_high_entropy),
            "route": ordered_route,
            "priority": priority,
            "explanation": "; ".join(explanation_parts) if explanation_parts else f"entropy within expected bounds for {category} file",
            "thresholds_used": {
                "high": threshold_high,
                "suspect": threshold_suspect,
            },
            "file_type": {
                "mime": mime_type,
                "category": category,
            },
        }
        return decision

    def _compute_stream_entropy(self, stream: IO[bytes], expected_length: int) -> float:
        counts = Counter()
        total = 0
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            counts.update(chunk)
            total += len(chunk)
        if total == 0 and expected_length > 0:
            total = expected_length
        return self._shannon_entropy_from_counts(counts, total)

    def _should_attempt_archive(
        self,
        mime_type: Optional[str],
        category: Optional[str],
        data_view: memoryview,
    ) -> bool:
        if category and category.lower() in {"archive", "document"}:
            return True
        if mime_type:
            lowered = mime_type.lower()
            if any(token in lowered for token in ("zip", "tar", "x-tar", "x-7z-compressed", "x-rar")):
                return True
        raw_bytes = data_view[:4].tobytes()
        return raw_bytes in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08") or raw_bytes.startswith(b"\x1F\x8B")

    def _select_time_budget(self, data_len: int) -> float:
        if data_len <= 10 * 1024 * 1024:
            return self.time_budget_small
        if data_len <= 100 * 1024 * 1024:
            return self.time_budget_medium
        return self.time_budget_large

    def _percentile(self, values: Sequence[float], percentile: float) -> float:
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        k = (len(sorted_vals) - 1) * (percentile / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_vals[int(k)]
        d0 = sorted_vals[int(f)] * (c - k)
        d1 = sorted_vals[int(c)] * (k - f)
        return d0 + d1

    def _shannon_entropy(self, data: Union[memoryview, bytes, bytearray]) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        return self._shannon_entropy_from_counts(counts, len(data))

    def _shannon_entropy_from_counts(self, counts: Counter, total: int) -> float:
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    def _round_entropy(self, value: float) -> float:
        return round(value, 3)

    def _append_route(self, decision: Dict[str, Any], route: str) -> None:
        if route not in decision["route"]:
            decision["route"].append(route)
            canonical_order = [
                "unpack_attempt",
                "packer_signature_detected",
                "inspect_archive_entries",
                "sandbox_immediate",
                "extract_embedded_windows",
            ]
            decision["route"] = [r for r in canonical_order if r in decision["route"]] + sorted(set(decision["route"]) - set(canonical_order))

    def _empty_result(self) -> Dict[str, Any]:
        return {
            "entropy": {
                "method": "shannon",
                "whole_file": 0.0,
                "mean": 0.0,
                "median": 0.0,
                "max": 0.0,
                "stddev": 0.0,
                "percentiles": {"p25": 0.0, "p50": 0.0, "p75": 0.0, "p90": 0.0},
                "chunk_size": self.chunk_size,
                "stride": self.stride,
                "window_count": 0,
                "compressibility_ratio": 0.0,
                "chi2": 0.0,
                "top_windows": [],
            },
            "archive": {
                "is_archive": False,
                "entry_count": 0,
                "top_entry_entropy": None,
                "entries_sample": [],
            },
            "decoded_streams": {
                "count": 0,
                "sample": [],
            },
        }

    def _is_mostly_text(self, payload: bytes, threshold: float = 0.7) -> bool:
        if not payload:
            return False
        # consider longer samples to avoid small-file bias
        sample = payload[: min(len(payload), 4096)]
        printable = sum(1 for byte in sample if 32 <= byte <= 126 or byte in (9, 10, 13))
        return (printable / len(sample)) >= threshold

    def _extract_uu_block(self, raw_bytes: bytes, start: int) -> Optional[bytes]:
        header_end = raw_bytes.find(b"\n", start)
        if header_end == -1:
            return None
        end_marker = raw_bytes.find(b"\nend", header_end)
        if end_marker == -1:
            return None
        return raw_bytes[start : end_marker + len(b"\nend")]

    def _decode_uu_block(self, block: bytes) -> Optional[bytes]:
        lines = block.splitlines()
        if len(lines) < 3:
            return None
        decoded = bytearray()
        for line in lines[1:]:
            stripped = line.strip()
            if stripped.lower() == b"end":
                break
            if not stripped or stripped == b"`":
                continue
            try:
                decoded.extend(binascii.a2b_uu(line + b"\n"))
            except binascii.Error:
                return None
        return bytes(decoded)

    def _compressibility_score(self, data_view: memoryview) -> float:
        """Return compressed_size / original_size using zlib. Lower ratio => higher entropy/compression-resistant."""
        try:
            raw = data_view.tobytes()
            if not raw:
                return 1.0
            # compress a sample for very large files
            sample = raw if len(raw) <= 512 * 1024 else raw[: 512 * 1024]
            compressed = zlib.compress(sample, level=6)
            ratio = len(compressed) / len(sample)
            return min(1.0, max(0.0, ratio))
        except Exception:
            return 1.0

    def _chi_squared_stat(self, data_view: memoryview) -> float:
        """Compute Pearson chi-squared statistic against uniform distribution over 256 buckets.
        For perfectly uniform random data the chi2 will be small; for structured data,
        chi2 will be large. We scale it so higher = more "non-uniform".
        """
        raw = data_view.tobytes()
        if not raw:
            return 0.0
        counts = [0] * 256
        for b in raw:
            counts[b] += 1
        total = len(raw)
        expected = total / 256.0
        chi2 = 0.0
        for c in counts:
            diff = c - expected
            chi2 += (diff * diff) / (expected if expected > 0 else 1.0)
        return chi2

    def _update_metrics(self, latency_ms: float, partial_reason: Optional[str], suspected_packed: bool) -> None:
        self._metrics["entropy_jobs_total"] += 1
        self._metrics["latency_sum_ms"] += latency_ms
        if partial_reason == "timeout":
            self._metrics["entropy_timeouts_total"] += 1
        if suspected_packed:
            self._metrics["suspected_packed_count"] += 1

    def _metrics_snapshot(self) -> Dict[str, Any]:
        jobs = self._metrics["entropy_jobs_total"]
        avg_latency = (self._metrics["latency_sum_ms"] / jobs) if jobs else 0.0
        return {
            "entropy_jobs_total": jobs,
            "entropy_timeouts_total": self._metrics["entropy_timeouts_total"],
            "suspected_packed_count": self._metrics["suspected_packed_count"],
            "avg_latency_ms": round(avg_latency, 3),
        }

    # Helper: optional calibration stub for offline dataset fitting
    def calibrate_from_samples(self, samples: Sequence[Tuple[bytes, int]]) -> Dict[str, Any]:
        """Given labeled samples: sequence of (raw_bytes, label) where label is 0 benign, 1 packed/malware.
        This routine computes simple ROC-style metrics and suggests tuned thresholds/weights.
        (This runs offline; included as helper only.)
        """
        # Simple collector
        records = []
        for raw, label in samples:
            mv = memoryview(raw).cast("B")
            e = self._shannon_entropy(mv)
            comp = self._compressibility_score(mv)
            chi2 = self._chi_squared_stat(mv)
            norm_e = min(1.0, e / 8.0)
            norm_c = max(0.0, min(1.0, 1.0 - comp))
            norm_chi = max(0.0, min(1.0, chi2 / (self.chi2_threshold * 2)))
            score = (
                self.detection_weights["entropy"] * norm_e
                + self.detection_weights["compressibility"] * norm_c
                + self.detection_weights["chi2"] * norm_chi
            )
            records.append((score, label))

        # compute simple statistics
        records.sort(key=lambda x: x[0])
        # return raw records — user can run ROC analysis externally
        return {"samples_count": len(records), "records": records}

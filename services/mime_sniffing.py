"""
MIME Sniffing Service - Enhanced python-magic Integration

CHANGELOG (2025-11-29):
- Lazy singleton initialization for python-magic to avoid unnecessary overhead
- Thread-safe magic instance with lock-protected access
- Sample-based detection with fallback to larger samples for ambiguous results
- LRU cache for repeated small file samples (1024 entries, keyed by SHA256)
- Graceful degradation when libmagic is unavailable (falls back to manual + filetype)
- Improved logging for magic init, fallbacks, and detection mismatches
- Preserved all existing structural validators and security checks
- Backward-compatible API - no changes to sniff_mime() return schema

Design decisions:
- Initial sample size: 16KB for fast detection, fallback to 128KB if generic result
- Cache keyed by SHA256 of sample (not full file) to balance memory and performance
- Magic unavailable flag prevents repeated init attempts after failure
- Lock protects both initialization and from_buffer calls
"""

import asyncio
import hashlib
import io
import json
import mimetypes
import struct
import threading
import zipfile
from functools import lru_cache
from typing import Any, Dict, Optional, Tuple, cast

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    magic = None

import filetype
from PIL import Image
from PyPDF2 import PdfReader

from utils.logger import get_logger

logger = get_logger(__name__)


class MimeSniffingService:
    """
    Advanced MIME type validation service that detects file type mismatches,
    validates file structure, and identifies potentially malicious files.
    """
    
    # Security limits
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB max upload
    MAGIC_SAMPLE_SIZE = 131072  # 128KB for detailed detection (fallback)
    MAGIC_QUICK_SAMPLE_SIZE = 16384  # 16KB for quick initial detection
    MAX_IMAGE_PIXELS = 178956970  # ~50000x50000 - prevent decompression bombs
    MAX_ZIP_ENTRIES = 10000  # Prevent zip bombs
    MAX_NESTED_DEPTH = 3  # Max nested archive depth
    
    # Generic MIME types that trigger larger sample re-detection
    GENERIC_MIME_TYPES = {
        "application/octet-stream",
        "text/plain",
        "unknown"
    }
    
    # Comprehensive MIME type to extension mapping
    MIME_TO_EXTENSION = {
        # Images
        "image/jpeg": ".jpg",
        "image/jpg": ".jpg",
        "image/png": ".png",
        "image/gif": ".gif",
        "image/bmp": ".bmp",
        "image/webp": ".webp",
        "image/tiff": ".tiff",
        "image/svg+xml": ".svg",
        "image/x-icon": ".ico",
        
        # Documents
        "application/pdf": ".pdf",
        "application/msword": ".doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
        "application/vnd.ms-excel": ".xls",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
        "application/vnd.ms-powerpoint": ".ppt",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
        "text/plain": ".txt",
        "text/csv": ".csv",
        "text/html": ".html",
        "text/xml": ".xml",
        "application/json": ".json",
        "application/rtf": ".rtf",
        
        # Archives
        "application/zip": ".zip",
        "application/x-zip-compressed": ".zip",
        "application/x-rar-compressed": ".rar",
        "application/x-7z-compressed": ".7z",
        "application/x-tar": ".tar",
        "application/gzip": ".gz",
        "application/x-bzip2": ".bz2",
        
        # Videos
        "video/mp4": ".mp4",
        "video/quicktime": ".mov",
        "video/x-matroska": ".mkv",
        "video/webm": ".webm",
        "video/x-flv": ".flv",
        "video/mpeg": ".mpeg",
        
        # Audio
        "audio/mpeg": ".mp3",
        "audio/wav": ".wav",
        "audio/ogg": ".ogg",
        "audio/webm": ".weba",
        "audio/aac": ".aac",
        "audio/flac": ".flac",
        "audio/x-m4a": ".m4a",
        
        # Executables
        "application/x-msdownload": ".exe",
        "application/x-executable": ".bin",
        "application/x-dosexec": ".exe",
        "application/x-mach-binary": ".bin",
        "application/x-elf": ".elf",
        "application/x-sharedlib": ".so",
        
        # Android
        "application/vnd.android.package-archive": ".apk",
        
        # Scripts
        "application/javascript": ".js",
        "application/x-javascript": ".js",
        "text/javascript": ".js",
        "application/x-python": ".py",
        "text/x-python": ".py",
        "application/x-sh": ".sh",
        "application/x-perl": ".pl",
        
        # Email
        "message/rfc822": ".eml",
        "application/vnd.ms-outlook": ".msg",
        
        # Other
        "application/octet-stream": ".bin",
    }
    
    # Category mapping for file types
    MIME_TO_CATEGORY = {
        "image/": "image",
        "video/": "video",
        "audio/": "audio",
        "application/pdf": "document",
        "application/msword": "document",
        "application/vnd.openxmlformats-officedocument.wordprocessingml": "document",
        "text/plain": "document",
        "text/html": "webpage",
        "application/vnd.ms-excel": "spreadsheet",
        "application/vnd.openxmlformats-officedocument.spreadsheetml": "spreadsheet",
        "text/csv": "spreadsheet",
        "message/rfc822": "email",
        "application/vnd.ms-outlook": "email",
        "application/zip": "archive",
        "application/x-rar": "archive",
        "application/x-7z": "archive",
        "application/x-tar": "archive",
        "application/gzip": "archive",
        "text/x-log": "log",
        "application/x-msdownload": "executable",
        "application/x-dosexec": "executable",
        "application/x-executable": "executable",
        "application/x-elf": "executable",
        "application/vnd.android.package-archive": "apk",
    }
    
    def __init__(self):
        """Initialize MIME sniffing service with lazy magic library initialization"""
        # Thread safety lock for magic library (init + detection)
        self._magic_lock = threading.Lock()
        
        # Lazy-initialized magic instances
        self._magic: Optional[Any] = None
        self._magic_description: Optional[Any] = None
        self._magic_available = MAGIC_AVAILABLE
        self._magic_init_attempted = False
        self._magic_init_error: Optional[str] = None
        
        # Cache for repeated samples (keyed by sample hash)
        # Exposed for testing as _magic_cache
        self._magic_cache = {}
        self._cache_max_size = 1024
        
        # Set PIL limits globally
        Image.MAX_IMAGE_PIXELS = self.MAX_IMAGE_PIXELS
        
        logger.info(
            f"MimeSniffingService initialized | "
            f"libmagic available: {self._magic_available} | "
            f"Max size: {self.MAX_FILE_SIZE / 1024 / 1024}MB | "
            f"Quick sample: {self.MAGIC_QUICK_SAMPLE_SIZE} bytes | "
            f"Full sample: {self.MAGIC_SAMPLE_SIZE} bytes | "
            f"Max pixels: {self.MAX_IMAGE_PIXELS}"
        )
    
    def _ensure_magic_initialized(self) -> bool:
        """
        Lazily initialize python-magic (thread-safe singleton pattern)
        
        Returns:
            True if magic is available and initialized, False otherwise
        """
        if self._magic_init_attempted:
            return self._magic_available
        
        with self._magic_lock:
            # Double-check after acquiring lock
            if self._magic_init_attempted:
                return self._magic_available
            
            self._magic_init_attempted = True
            
            if not MAGIC_AVAILABLE:
                self._magic_available = False
                self._magic_init_error = "python-magic library not installed"
                logger.warning(
                    "python-magic not available - falling back to manual detection. "
                    "Install with: pip install python-magic (Linux/Mac) or "
                    "pip install python-magic-bin (Windows)"
                )
                return False
            
            try:
                # Initialize both MIME and description detectors (cast to silence type checkers)
                # runtime guard above (MAGIC_AVAILABLE) ensures `magic` is not None
                self._magic = cast(Any, magic).Magic(mime=True)
                self._magic_description = cast(Any, magic).Magic()
                
                # Validate that the Magic instances were created successfully and expose expected methods
                if self._magic is None or not hasattr(self._magic, "from_buffer") or \
                   self._magic_description is None or not hasattr(self._magic_description, "from_buffer"):
                    raise RuntimeError(
                        "Magic library initialization failed: Magic() returned None or missing expected methods. "
                        "Ensure libmagic is properly installed and python-magic is compatible."
                    )
                
                # Test with a known signature
                test_result = self._magic.from_buffer(b'%PDF-1.4')
                if not test_result or test_result == "application/octet-stream":
                    raise RuntimeError(
                        "Magic library not functioning correctly. "
                        "Ensure libmagic is properly installed: "
                        "apt-get install libmagic1 (Debian/Ubuntu) / "
                        "brew install libmagic (macOS) / "
                        "pip install python-magic-bin (Windows)"
                    )
                
                self._magic_available = True
                logger.info(f"python-magic initialized successfully | Test result: {test_result}")
                return True
                
            except Exception as e:
                self._magic_available = False
                self._magic_init_error = str(e)
                logger.error(
                    f"Failed to initialize python-magic: {e}. "
                    f"Falling back to manual detection.",
                    exc_info=True
                )
                return False
    
    def _get_sample_hash(self, sample: bytes) -> str:
        """Calculate SHA256 hash of sample for caching"""
        return hashlib.sha256(sample).hexdigest()
    
    def _cache_get(self, sample_hash: str) -> Optional[Tuple[str, str]]:
        """Get cached magic result"""
        return self._magic_cache.get(sample_hash)
    
    def _cache_set(self, sample_hash: str, result: Tuple[str, str]):
        """Set cached magic result with LRU eviction"""
        if len(self._magic_cache) >= self._cache_max_size:
            # Simple LRU: remove oldest (first) entry
            oldest_key = next(iter(self._magic_cache))
            del self._magic_cache[oldest_key]
        self._magic_cache[sample_hash] = result
    
    async def sniff_mime(
        self, 
        file_data: bytes, 
        claimed_mime: Optional[str] = None,
        filename: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Main entry point - Performs all 4 core MIME validation tasks with security hardening
        
        Args:
            file_data: Binary file data
            claimed_mime: MIME type from browser/user (optional)
            filename: Original filename (optional)
            
        Returns:
            Standardized MIME validation result dictionary with action field
        """
        try:
            # CRITICAL: Size check FIRST - prevent memory exhaustion
            file_size = len(file_data)
            if file_size > self.MAX_FILE_SIZE:
                logger.warning(f"File rejected: size {file_size} exceeds limit {self.MAX_FILE_SIZE}")
                return {
                    "claimed_mime": claimed_mime or "unknown",
                    "detected_mime": "unknown",
                    "detected_mime_raw": "unknown",
                    "mime_match": False,
                    "file_extension": None,
                    "expected_extension": None,
                    "extension_match": None,
                    "magic_byte_summary": "File too large",
                    "suspicious": True,
                    "reason": f"File size ({file_size / 1024 / 1024:.2f}MB) exceeds maximum allowed ({self.MAX_FILE_SIZE / 1024 / 1024}MB)",
                    "confidence": 0.0,
                    "category": "unknown",
                    "extension": None,
                    "action": "reject",
                    "file_size": file_size
                }
            
            # Task 1: Extract claimed MIME (if provided)
            claimed = claimed_mime or self._extract_claimed_mime(filename)
            claimed_normalized = self._normalize_mime(claimed) if claimed else None
            
            # Task 2: Detect actual MIME using multiple methods
            detected_mime_raw, magic_summary, filetype_result = await self._detect_actual_mime(file_data)
            detected_mime = self._normalize_mime(detected_mime_raw)
            
            # Check for dangerous patterns (polyglot, double extensions)
            polyglot_suspicious, polyglot_reason = self._check_dangerous_patterns(
                filename, file_data, detected_mime
            )
            
            # Task 3: Compare claimed vs actual MIME (detect subterfuge)
            is_match, is_suspicious, reason = self._compare_mime_types(
                claimed_normalized, 
                detected_mime,
                filetype_result
            )
            
            # Get expected extensions
            claimed_extension = self._get_extension_from_mime(claimed_normalized) if claimed_normalized else None
            detected_extension = self._get_extension_from_mime(detected_mime)
            filename_extension = self._extract_extension_from_filename(filename) if filename else None
            
            # Check extension match (returns None if unknown)
            extension_match = self._check_extension_match(
                filename_extension,
                claimed_extension,
                detected_extension
            )
            
            # Task 4: Enrich with structural checks (run in thread pool)
            structural_validation = await self._validate_structure(file_data, detected_mime)
            
            # Combine all suspicion signals
            final_suspicious = (
                is_suspicious or 
                structural_validation.get("suspicious", False) or
                polyglot_suspicious
            )
            
            # Build comprehensive reason
            reasons = []
            if reason:
                reasons.append(reason)
            if structural_validation.get("reason"):
                reasons.append(structural_validation["reason"])
            if polyglot_reason:
                reasons.append(polyglot_reason)
            
            final_reason = " | ".join(reasons) if reasons else None
            
            # Calculate confidence score with penalties
            confidence = self._calculate_confidence(
                is_match,
                extension_match,
                structural_validation,
                filetype_result,
                polyglot_suspicious
            )
            
            # Determine file category
            category = self._get_category(detected_mime)
            
            # Determine security action
            action = self._determine_action(
                final_suspicious,
                confidence,
                detected_mime,
                structural_validation
            )
            
            # Build standardized output
            result = {
                "claimed_mime": claimed or "unknown",
                "detected_mime": detected_mime,
                "detected_mime_raw": detected_mime_raw,
                "mime_match": is_match,
                "file_extension": filename_extension or detected_extension,
                "expected_extension": detected_extension,
                "extension_match": extension_match,
                "magic_byte_summary": magic_summary,
                "suspicious": final_suspicious,
                "reason": final_reason,
                "confidence": confidence,
                "category": category,
                "extension": detected_extension,
                "structural_validation": structural_validation,
                "filetype_cross_check": filetype_result,
                "sha256": None,
                "action": action,
                "file_size": file_size
            }
            
            if final_suspicious:
                logger.warning(
                    f"SUSPICIOUS FILE DETECTED | "
                    f"Action: {action} | "
                    f"Reason: {final_reason} | "
                    f"Claimed: {claimed} | "
                    f"Detected: {detected_mime}"
                )
            else:
                logger.info(
                    f"File validated successfully | "
                    f"Type: {detected_mime} | "
                    f"Confidence: {confidence}"
                )
            
            return result
            
        except Exception as e:
            logger.error(f"Error during MIME sniffing: {e}", exc_info=True)
            return {
                "claimed_mime": claimed_mime or "unknown",
                "detected_mime": "unknown",
                "detected_mime_raw": "unknown",
                "mime_match": False,
                "file_extension": None,
                "expected_extension": None,
                "extension_match": None,
                "magic_byte_summary": f"Error: {str(e)}",
                "suspicious": True,
                "reason": f"MIME detection failed: {str(e)}",
                "confidence": 0.0,
                "category": "unknown",
                "extension": None,
                "sha256": None,
                "action": "quarantine",
                "error": str(e)
            }
    
    def _calculate_hash(self, file_data: bytes) -> str:
        """Calculate SHA256 hash (blocking operation)"""
        return hashlib.sha256(file_data).hexdigest()
    
    def _normalize_mime(self, mime: str) -> str:
        """Normalize MIME type by removing charset and trimming"""
        if not mime:
            return ""
        # Remove charset parameter
        mime = mime.split(';')[0].strip().lower()
        return mime
    
    def _extract_claimed_mime(self, filename: Optional[str]) -> Optional[str]:
        """Extract claimed MIME from filename extension with fallback to stdlib"""
        if not filename:
            return None
        
        ext = self._extract_extension_from_filename(filename)
        if not ext:
            return None
        
        # Try reverse lookup first
        for mime, extension in self.MIME_TO_EXTENSION.items():
            if extension.lower() == ext.lower():
                return mime
        
        # Fallback to Python's mimetypes
        guessed, _ = mimetypes.guess_type(filename)
        if guessed:
            logger.debug(f"Using mimetypes fallback for {filename}: {guessed}")
        return guessed
    
    async def _detect_actual_mime(self, file_data: bytes) -> Tuple[str, str, Optional[Dict[str, str]]]:
        """
        Detect actual MIME type using multiple methods with cross-validation
        Returns (detected_mime, magic_summary, filetype_result)
        """
        # Run detections in parallel
        magic_result, filetype_result = await asyncio.gather(
            asyncio.to_thread(self._detect_with_magic, file_data),
            asyncio.to_thread(self._detect_with_filetype, file_data[:8192])
        )
        
        magic_mime, magic_summary = magic_result
        
        # Determine best MIME type
        detected_mime = self._choose_best_mime(magic_mime, filetype_result, file_data)
        
        # If still generic, try text format detection
        if detected_mime in self.GENERIC_MIME_TYPES:
            text_mime = self._detect_text_format(file_data[:1024])
            if text_mime and text_mime not in self.GENERIC_MIME_TYPES:
                logger.debug(f"Text format detection improved result: {text_mime}")
                detected_mime = text_mime
                magic_summary = f"{magic_summary} | Text analysis: {text_mime}"
        
        return detected_mime, magic_summary, filetype_result
    
    def _detect_with_magic(self, file_data: bytes) -> Tuple[str, str]:
        """
        Detect MIME using python-magic with adaptive sampling and caching
        Returns (mime_type, description/summary)
        """
        # Try to initialize magic if not already done
        if not self._ensure_magic_initialized():
            # Magic unavailable - return error info
            error_msg = f"magic_unavailable: {self._magic_init_error or 'not installed'}"
            logger.debug(f"Magic detection skipped: {error_msg}")
            return "unknown", error_msg
        
        try:
            # Step 1: Quick detection with small sample
            quick_sample_size = min(len(file_data), self.MAGIC_QUICK_SAMPLE_SIZE)
            quick_sample = file_data[:quick_sample_size]
            quick_hash = self._get_sample_hash(quick_sample)
            
            # Check cache
            cached_result = self._cache_get(quick_hash)
            if cached_result:
                logger.debug(f"Cache hit for sample (size={quick_sample_size})")
                return cached_result
            
            # Detect with quick sample (thread-safe)
            with self._magic_lock:
                # Localize and cast instances so static checkers know they are not None
                magic_inst = cast(Any, self._magic)
                desc_inst = cast(Any, self._magic_description)
                if magic_inst is None or desc_inst is None or not hasattr(magic_inst, "from_buffer") or not hasattr(desc_inst, "from_buffer"):
                    raise RuntimeError("Magic instance not initialized properly")
                detected_mime = magic_inst.from_buffer(quick_sample)
                magic_desc = desc_inst.from_buffer(quick_sample)
            
            summary_parts = [f"magic(quick={quick_sample_size}B): {magic_desc[:80]}"]
            
            # Step 2: If result is generic AND we have more data, try larger sample
            if detected_mime in self.GENERIC_MIME_TYPES and len(file_data) > quick_sample_size:
                logger.debug(
                    f"Generic result '{detected_mime}' from quick sample, "
                    f"retrying with larger sample"
                )
                
                larger_sample_size = min(len(file_data), self.MAGIC_SAMPLE_SIZE)
                larger_sample = file_data[:larger_sample_size]
                
                with self._magic_lock:
                    magic_inst = cast(Any, self._magic)
                    desc_inst = cast(Any, self._magic_description)
                    if magic_inst is None or desc_inst is None or not hasattr(magic_inst, "from_buffer") or not hasattr(desc_inst, "from_buffer"):
                        raise RuntimeError("Magic instance not initialized properly")
                    redetected_mime = magic_inst.from_buffer(larger_sample)
                    redetected_desc = desc_inst.from_buffer(larger_sample)
                
                # Use redetected if it's more specific
                if redetected_mime not in self.GENERIC_MIME_TYPES:
                    detected_mime = redetected_mime
                    magic_desc = redetected_desc
                    summary_parts.append(f"fallback({larger_sample_size}B): {magic_desc[:80]}")
                    logger.debug(f"Larger sample improved result: {detected_mime}")
                else:
                    summary_parts.append(f"fallback({larger_sample_size}B): still generic")
            
            magic_summary = " | ".join(summary_parts)
            
            # Cache the result
            result = (detected_mime, magic_summary)
            self._cache_set(quick_hash, result)
            
            return result
            
        except Exception as e:
            error_msg = f"Magic error: {str(e)}"
            logger.error(f"Magic detection failed: {e}", exc_info=True)
            return "unknown", error_msg
    
    def _detect_with_filetype(self, file_data: bytes) -> Optional[Dict[str, str]]:
        """
        Cross-validate MIME detection using filetype library
        Returns filetype result or None if detection fails
        """
        try:
            kind = filetype.guess(file_data)
            if kind:
                return {
                    "mime": kind.mime,
                    "extension": kind.extension
                }
            return None
        except Exception as e:
            logger.debug(f"Filetype detection failed: {e}")
            return None
    
    def _choose_best_mime(
        self, 
        magic_mime: str, 
        filetype_result: Optional[Dict[str, str]],
        file_data: bytes
    ) -> str:
        """
        Choose the most specific MIME type from multiple detections
        """
        # If magic is specific (not generic), use it
        if magic_mime not in self.GENERIC_MIME_TYPES:
            # But check if filetype disagrees significantly
            if filetype_result and filetype_result["mime"] != magic_mime:
                ft_mime = filetype_result["mime"]
                # If filetype is more specific, prefer it
                if ft_mime not in self.GENERIC_MIME_TYPES:
                    logger.warning(
                        f"Detection mismatch: magic={magic_mime}, filetype={ft_mime}. "
                        f"Using filetype result as more specific."
                    )
                    return ft_mime
            return magic_mime
        
        # Magic is generic, try filetype
        if filetype_result and filetype_result["mime"] not in ["application/octet-stream"]:
            logger.debug(f"Using filetype result over generic magic: {filetype_result['mime']}")
            return filetype_result["mime"]
        
        # Both are generic, try manual signature detection
        manual_mime, _ = self._manual_signature_detection(file_data)
        if manual_mime != "unknown":
            logger.debug(f"Using manual signature detection: {manual_mime}")
            return manual_mime
        
        # Last resort - return magic result even if generic
        return magic_mime
    
    def _detect_text_format(self, sample: bytes) -> Optional[str]:
        """
        Detect text-based formats that magic often misidentifies
        """
        try:
            # Try to decode as UTF-8
            text = sample.decode('utf-8', errors='ignore').lower()
            
            # HTML detection
            if '<!doctype html' in text or '<html' in text:
                return "text/html"
            
            # XML detection
            if text.strip().startswith('<?xml'):
                # Check for specific XML types
                if '<svg' in text:
                    return "image/svg+xml"
                return "text/xml"
            
            # SVG without XML declaration
            if '<svg' in text:
                return "image/svg+xml"
            
            # JSON detection
            text_stripped = text.strip()
            if (text_stripped.startswith('{') and text_stripped.endswith('}')) or \
               (text_stripped.startswith('[') and text_stripped.endswith(']')):
                try:
                    json.loads(sample.decode('utf-8'))
                    return "application/json"
                except:
                    pass
            
            # JavaScript detection
            if 'function' in text or 'var ' in text or 'const ' in text or 'let ' in text:
                return "application/javascript"
            
            return None
            
        except Exception as e:
            logger.debug(f"Text format detection failed: {e}")
            return None
    
    def _manual_signature_detection(self, file_data: bytes) -> Tuple[str, str]:
        """
        Manual signature-based detection with improved ZIP handling
        Returns (mime_type, description)
        """
        if len(file_data) < 8:
            return "unknown", "File too small for detection"
        
        # Check for ZIP-based formats first (requires special handling)
        if file_data[:4] == b'PK\x03\x04':
            return self._detect_zip_based_format(file_data)
        
        # Check for RIFF-based formats
        if file_data[:4] == b'RIFF' and len(file_data) >= 12:
            return self._detect_riff_format(file_data)
        
        # Define signatures (magic bytes)
        signatures = [
            # Images
            (b'\xff\xd8\xff', "image/jpeg", "JPEG image"),
            (b'\x89PNG\r\n\x1a\n', "image/png", "PNG image"),
            (b'GIF87a', "image/gif", "GIF image (87a)"),
            (b'GIF89a', "image/gif", "GIF image (89a)"),
            (b'BM', "image/bmp", "BMP image"),
            (b'\x00\x00\x01\x00', "image/x-icon", "ICO icon"),
            
            # Documents
            (b'%PDF-', "application/pdf", "PDF document"),
            (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', "application/msword", "MS Office document (legacy)"),
            
            # Archives
            (b'Rar!\x1a\x07', "application/x-rar-compressed", "RAR archive"),
            (b'7z\xbc\xaf\x27\x1c', "application/x-7z-compressed", "7-Zip archive"),
            (b'\x1f\x8b\x08', "application/gzip", "Gzip compressed"),
            (b'BZh', "application/x-bzip2", "Bzip2 compressed"),
            
            # Executables
            (b'MZ', "application/x-dosexec", "DOS/Windows executable"),
            (b'\x7fELF', "application/x-elf", "ELF executable"),
            (b'\xfe\xed\xfa\xce', "application/x-mach-binary", "Mach-O executable (32-bit)"),
            (b'\xfe\xed\xfa\xcf', "application/x-mach-binary", "Mach-O executable (64-bit)"),
            
            # Media
            (b'ID3', "audio/mpeg", "MP3 audio"),
            (b'\xff\xfb', "audio/mpeg", "MP3 audio (no ID3)"),
            (b'OggS', "audio/ogg", "Ogg audio"),
        ]
        
        # Check MP4 variants (at offset 4)
        if len(file_data) >= 12:
            ftyp = file_data[4:8]
            if ftyp == b'ftyp':
                subtype = file_data[8:12]
                if subtype in [b'isom', b'mp41', b'mp42', b'mmp4', b'avc1']:
                    return "video/mp4", "MP4 video"
        
        # Check each signature
        for sig_bytes, mime, desc in signatures:
            if len(file_data) >= len(sig_bytes):
                if file_data[:len(sig_bytes)] == sig_bytes:
                    return mime, desc
        
        return "unknown", "No matching signature found"
    
    def _detect_zip_based_format(self, file_data: bytes) -> Tuple[str, str]:
        """
        Properly detect ZIP-based formats by parsing the archive
        """
        try:
            with zipfile.ZipFile(io.BytesIO(file_data), 'r') as zf:
                file_list = zf.namelist()
                
                # Check for Office Open XML documents
                if '[Content_Types].xml' in file_list:
                    try:
                        content_types = zf.read('[Content_Types].xml').decode('utf-8')
                        
                        if 'wordprocessingml' in content_types:
                            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "Word document"
                        elif 'spreadsheetml' in content_types:
                            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Excel spreadsheet"
                        elif 'presentationml' in content_types:
                            return "application/vnd.openxmlformats-officedocument.presentationml.presentation", "PowerPoint presentation"
                    except Exception as e:
                        logger.debug(f"Failed to parse Content_Types.xml: {e}")
                
                # Check for OpenDocument formats
                if 'mimetype' in file_list:
                    try:
                        mimetype = zf.read('mimetype').decode('utf-8').strip()
                        if mimetype:
                            return mimetype, f"OpenDocument ({mimetype})"
                    except Exception as e:
                        logger.debug(f"Failed to read mimetype file: {e}")
                
                # Check for APK (Android Package)
                if 'AndroidManifest.xml' in file_list:
                    return "application/vnd.android.package-archive", "Android APK"
                
                # Check for JAR (Java Archive)
                if 'META-INF/MANIFEST.MF' in file_list:
                    return "application/java-archive", "JAR file"
                
        except zipfile.BadZipFile:
            logger.debug("Invalid ZIP structure")
        except Exception as e:
            logger.debug(f"Error analyzing ZIP: {e}")
        
        return "application/zip", "ZIP archive"
    
    def _detect_riff_format(self, file_data: bytes) -> Tuple[str, str]:
        """
        Properly detect RIFF-based formats by checking format identifier
        """
        format_id = file_data[8:12]
        
        if format_id == b'WEBP':
            return "image/webp", "WebP image"
        elif format_id == b'WAVE':
            return "audio/wav", "WAV audio"
        elif format_id == b'AVI ':
            return "video/x-msvideo", "AVI video"
        else:
            return "application/octet-stream", f"Unknown RIFF format: {format_id}"
    
    async def _validate_structure(
        self, 
        file_data: bytes, 
        mime_type: str
    ) -> Dict[str, Any]:
        """
        Task 4: Enrich with structural checks
        Validates authenticity of file structure (runs validators in thread pool)
        """
        result = {
            "validated": False,
            "suspicious": False,
            "reason": None,
            "details": {}
        }
        
        try:
            if mime_type.startswith("image/"):
                return await asyncio.to_thread(self._validate_image_structure_sync, file_data, mime_type)
            elif mime_type == "application/pdf":
                return await asyncio.to_thread(self._validate_pdf_structure_sync, file_data)
            elif "wordprocessingml" in mime_type or "spreadsheetml" in mime_type:
                return await asyncio.to_thread(self._validate_office_structure_sync, file_data, mime_type)
            elif "zip" in mime_type or mime_type.startswith("application/x-rar"):
                return await asyncio.to_thread(self._validate_archive_structure_sync, file_data, mime_type)
            elif mime_type in ["application/x-dosexec", "application/x-executable", "application/x-elf"]:
                return await asyncio.to_thread(self._validate_executable_structure_sync, file_data, mime_type)
            else:
                result["validated"] = True
                result["details"]["message"] = "No specific structural validation for this type"
                return result
                
        except Exception as e:
            result["suspicious"] = True
            result["reason"] = f"Structural validation failed: {str(e)}"
            result["details"]["error"] = str(e)
            logger.error(f"Structural validation error: {e}", exc_info=True)
            return result
    
    def _validate_image_structure_sync(
        self, 
        file_data: bytes, 
        mime_type: str
    ) -> Dict[str, Any]:
        """Validate image file structure and headers (BLOCKING)"""
        result = {"validated": False, "suspicious": False, "reason": None, "details": {}}
        
        try:
            # Use verify() first for safety
            img = Image.open(io.BytesIO(file_data))
            img.verify()
            
            # Now safe to open again for info
            img = Image.open(io.BytesIO(file_data))
            
            result["validated"] = True
            result["details"] = {
                "format": img.format,
                "mode": img.mode,
                "size": img.size,
                "width": img.width,
                "height": img.height
            }
            
            # Check for decompression bomb
            pixel_count = img.width * img.height
            if pixel_count > self.MAX_IMAGE_PIXELS:
                result["suspicious"] = True
                result["reason"] = f"Decompression bomb: {pixel_count} pixels exceeds limit"
            
            # Check for JPEG specific validations
            if mime_type == "image/jpeg":
                if not file_data.startswith(b'\xff\xd8\xff'):
                    result["suspicious"] = True
                    result["reason"] = "Invalid JPEG SOI marker"
            
            # Check for PNG specific validations
            elif mime_type == "image/png":
                if not file_data.startswith(b'\x89PNG\r\n\x1a\n'):
                    result["suspicious"] = True
                    result["reason"] = "Invalid PNG signature"
            
            img.close()
            
        except Image.DecompressionBombError as e:
            result["suspicious"] = True
            result["reason"] = f"Decompression bomb detected: {str(e)}"
            result["details"]["error"] = str(e)
        except Exception as e:
            result["suspicious"] = True
            result["reason"] = f"Image validation failed: {str(e)}"
            result["details"]["error"] = str(e)
        
        return result
    
    def _validate_pdf_structure_sync(self, file_data: bytes) -> Dict[str, Any]:
        """Validate PDF file structure (BLOCKING)"""
        result = {"validated": False, "suspicious": False, "reason": None, "details": {}}
        
        try:
            # Check PDF header
            if not file_data.startswith(b'%PDF-'):
                result["suspicious"] = True
                result["reason"] = "Invalid PDF header"
                return result
            
            # Try to read with PyPDF2
            pdf = PdfReader(io.BytesIO(file_data))
            
            result["validated"] = True
            result["details"] = {
                "num_pages": len(pdf.pages),
                "is_encrypted": pdf.is_encrypted
            }
            
            # Safely extract metadata
            if pdf.metadata:
                try:
                    result["details"]["metadata"] = {
                        k: str(v) for k, v in pdf.metadata.items() if v
                    }
                except:
                    result["details"]["metadata"] = "Error reading metadata"
            
            # Check for JavaScript (search in raw bytes more carefully)
            js_indicators = [b'/JavaScript', b'/JS', b'/Launch', b'/SubmitForm']
            for indicator in js_indicators:
                if indicator in file_data:
                    result["suspicious"] = True
                    result["reason"] = f"PDF contains {indicator.decode('latin-1')} (potential exploit)"
                    break
            
            # Check for embedded files
            if b'/EmbeddedFile' in file_data:
                result["details"]["has_embedded_files"] = True
                if not result["suspicious"]:
                    result["suspicious"] = True
                    result["reason"] = "PDF contains embedded files"
            
        except Exception as e:
            result["suspicious"] = True
            result["reason"] = f"PDF validation failed: {str(e)}"
            result["details"]["error"] = str(e)
        
        return result
    
    def _validate_office_structure_sync(
        self, 
        file_data: bytes, 
        mime_type: str
    ) -> Dict[str, Any]:
        """Validate Office document structure (BLOCKING)"""
        result = {"validated": False, "suspicious": False, "reason": None, "details": {}}
        
        try:
            # Office documents are ZIP files
            with zipfile.ZipFile(io.BytesIO(file_data), 'r') as zip_file:
                file_list = zip_file.namelist()
                
                # Check entry count
                if len(file_list) > self.MAX_ZIP_ENTRIES:
                    result["suspicious"] = True
                    result["reason"] = f"Too many entries in Office document ({len(file_list)})"
                    return result
                
                # Check for required Office document structure
                has_content_types = '[Content_Types].xml' in file_list
                has_rels = any('_rels' in f for f in file_list)
                
                if not has_content_types:
                    result["suspicious"] = True
                    result["reason"] = "Missing [Content_Types].xml - invalid Office document"
                    return result
                
                result["validated"] = True
                result["details"] = {
                    "has_content_types": has_content_types,
                    "has_rels": has_rels,
                    "file_count": len(file_list)
                }
                
                # Check for macros
                macro_files = [f for f in file_list if 'vbaProject' in f or f.endswith('.bin')]
                if macro_files:
                    result["details"]["has_macros"] = True
                    result["details"]["macro_files"] = macro_files
                    result["suspicious"] = True
                    result["reason"] = f"Document contains {len(macro_files)} macro file(s)"
                
        except zipfile.BadZipFile:
            result["suspicious"] = True
            result["reason"] = "Invalid ZIP structure for Office document"
        except Exception as e:
            result["suspicious"] = True
            result["reason"] = f"Office document validation failed: {str(e)}"
            result["details"]["error"] = str(e)
        
        return result
    
    def _validate_archive_structure_sync(
        self, 
        file_data: bytes, 
        mime_type: str
    ) -> Dict[str, Any]:
        """Validate archive file structure (BLOCKING)"""
        result = {"validated": False, "suspicious": False, "reason": None, "details": {}}
        
        try:
            if "zip" in mime_type:
                with zipfile.ZipFile(io.BytesIO(file_data), 'r') as zip_file:
                    file_list = zip_file.namelist()
                    
                    # Check for zip bomb
                    if len(file_list) > self.MAX_ZIP_ENTRIES:
                        result["suspicious"] = True
                        result["reason"] = f"Zip bomb detected: {len(file_list)} entries"
                        return result
                    
                    result["validated"] = True
                    result["details"] = {
                        "file_count": len(file_list),
                        "compression_type": "ZIP"
                    }
                    
                    # Check for suspicious nested archives
                    nested_archives = [f for f in file_list if f.lower().endswith(('.zip', '.rar', '.7z', '.tar', '.gz'))]
                    if nested_archives:
                        result["details"]["nested_archives"] = len(nested_archives)
                        if len(nested_archives) > 5:
                            result["suspicious"] = True
                            result["reason"] = f"Suspicious: {len(nested_archives)} nested archives"
                    
                    # Check for executables
                    executables = [f for f in file_list if f.lower().endswith(('.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js'))]
                    if executables:
                        result["suspicious"] = True
                        result["reason"] = f"Archive contains {len(executables)} executable file(s)"
                        result["details"]["executables"] = executables[:10]  # Limit list
            else:
                result["validated"] = True
                result["details"]["message"] = "Basic archive validation only"
                
        except Exception as e:
            result["suspicious"] = True
            result["reason"] = f"Archive validation failed: {str(e)}"
            result["details"]["error"] = str(e)
        
        return result
    
    def _validate_executable_structure_sync(
        self, 
        file_data: bytes, 
        mime_type: str
    ) -> Dict[str, Any]:
        """Validate executable file structure (BLOCKING)"""
        result = {"validated": False, "suspicious": True, "reason": None, "details": {}}
        
        try:
            # Check for PE (Windows) executable
            if file_data.startswith(b'MZ'):
                result["details"]["format"] = "PE (Windows Executable)"
                result["validated"] = True
                result["reason"] = "Executable file detected (inherently high risk)"
                
                # Try to find PE header
                if len(file_data) > 0x3C + 4:
                    try:
                        pe_offset = struct.unpack('<I', file_data[0x3C:0x3C+4])[0]
                        if pe_offset < len(file_data) - 4:
                            pe_signature = file_data[pe_offset:pe_offset+4]
                            if pe_signature == b'PE\x00\x00':
                                result["details"]["valid_pe"] = True
                            else:
                                result["reason"] = "Invalid PE signature (possible malformed executable)"
                    except struct.error:
                        result["reason"] = "Corrupted PE header"
            
            # Check for ELF (Linux) executable
            elif file_data.startswith(b'\x7fELF'):
                result["details"]["format"] = "ELF (Linux Executable)"
                result["validated"] = True
                result["reason"] = "Executable file detected (inherently high risk)"
            
            # Check for Mach-O (macOS) executable
            elif file_data[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
                result["details"]["format"] = "Mach-O (macOS Executable)"
                result["validated"] = True
                result["reason"] = "Executable file detected (inherently high risk)"
            
            else:
                result["reason"] = "Unknown executable format"
                
        except Exception as e:
            result["reason"] = f"Executable validation failed: {str(e)}"
            result["details"]["error"] = str(e)
        
        return result
    
    def _get_extension_from_mime(self, mime_type: str) -> Optional[str]:
        """Get expected file extension from MIME type"""
        if not mime_type or mime_type == "unknown":
            return None
        
        return self.MIME_TO_EXTENSION.get(mime_type.lower())
    
    def _extract_extension_from_filename(self, filename: str) -> Optional[str]:
        """Extract file extension from filename"""
        if not filename or '.' not in filename:
            return None
        
        return '.' + filename.rsplit('.', 1)[1].lower()
    
    def _check_extension_match(
        self, 
        filename_ext: Optional[str],
        claimed_ext: Optional[str],
        detected_ext: Optional[str]
    ) -> Optional[bool]:
        """
        Check if file extension matches expected extension
        Returns None if unknown, True if match, False if mismatch
        """
        if not filename_ext:
            return None  # Unknown - no filename extension to validate
        
        # Check against detected extension (primary)
        if detected_ext and filename_ext.lower() == detected_ext.lower():
            return True
        
        # Check against claimed extension (secondary)
        if claimed_ext and filename_ext.lower() == claimed_ext.lower():
            return True
        
        return False
    
    def _calculate_confidence(
        self,
        mime_match: bool,
        extension_match: Optional[bool],
        structural_validation: Dict[str, Any],
        filetype_result: Optional[Dict[str, str]],
        polyglot_detected: bool
    ) -> float:
        """Calculate confidence score with penalties (0.0 to 1.0)"""
        score = 0.0
        
        # MIME match contributes 40%
        if mime_match:
            score += 0.40
        
        # Extension match contributes 20% (only if explicitly True)
        if extension_match is True:
            score += 0.20
        elif extension_match is False:
            score -= 0.15  # Penalty for mismatch
        
        # Structural validation contributes 30%
        if structural_validation.get("validated"):
            if not structural_validation.get("suspicious"):
                score += 0.30
            else:
                score += 0.10  # Reduced credit if suspicious
                score -= 0.15  # Penalty for suspicion
        
        # Cross-check with filetype contributes 10%
        if filetype_result:
            score += 0.10
        
        # Polyglot penalty
        if polyglot_detected:
            score -= 0.25
        
        return max(0.0, min(1.0, round(score, 2)))
    
    def _determine_action(
        self,
        suspicious: bool,
        confidence: float,
        mime_type: str,
        structural: Dict[str, Any]
    ) -> str:
        """
        Determine security action based on analysis
        
        Returns:
            - "reject": Immediate rejection
            - "quarantine": Isolate for manual review
            - "force_sandbox": Require sandbox analysis
            - "static_analysis": Require static analysis
            - "proceed": Allow file through
        """
        # Immediate reject for executables
        if mime_type in ["application/x-dosexec", "application/x-executable", "application/x-elf", "application/x-msdownload"]:
            return "quarantine"
        
        # High suspicion + low confidence = quarantine
        if suspicious and confidence < 0.25:
            return "quarantine"
        
        # High suspicion + medium confidence = sandbox
        if suspicious and confidence < 0.50:
            return "force_sandbox"
        
        # Medium suspicion = static analysis
        if suspicious:
            return "static_analysis"
        
        # Low confidence even if not suspicious
        if confidence < 0.50:
            return "static_analysis"
        
        return "proceed"
    
    def _get_category(self, mime_type: str) -> str:
        """Determine file category from MIME type"""
        if not mime_type or mime_type == "unknown":
            return "unknown"
        
        # Check exact matches first
        for mime_pattern, category in self.MIME_TO_CATEGORY.items():
            if mime_pattern in mime_type:
                return category
        
        # Default to "other"
        return "other"
    
    def _compare_mime_types(
        self,
        claimed_mime: Optional[str],
        detected_mime: str,
        filetype_result: Optional[Dict[str, str]]
    ) -> Tuple[bool, bool, Optional[str]]:
        """
        Compare claimed vs detected MIME types to detect subterfuge
        
        Args:
            claimed_mime: MIME type from user/browser (normalized)
            detected_mime: MIME type from magic bytes (normalized)
            filetype_result: Cross-check result from filetype library
            
        Returns:
            Tuple of (is_match, is_suspicious, reason)
        """
        is_match = False
        is_suspicious = False
        reason = None
        
        # If no claimed MIME, can't compare
        if not claimed_mime or claimed_mime == "unknown":
            # But if detected is dangerous, mark suspicious
            if detected_mime in ["application/x-dosexec", "application/x-executable", 
                                "application/x-elf", "application/x-msdownload"]:
                is_suspicious = True
                reason = f"Executable detected without explicit MIME declaration"
            return is_match, is_suspicious, reason
        
        # Exact match
        if claimed_mime == detected_mime:
            is_match = True
            return is_match, is_suspicious, reason
        
        # Check for known compatible MIME types (aliases)
        compatible_pairs = [
            ("image/jpg", "image/jpeg"),
            ("image/jpeg", "image/jpg"),
            ("application/zip", "application/x-zip-compressed"),
            ("application/x-zip-compressed", "application/zip"),
            ("application/javascript", "text/javascript"),
            ("text/javascript", "application/javascript"),
            ("application/x-javascript", "text/javascript"),
            ("text/javascript", "application/x-javascript"),
        ]
        
        for pair in compatible_pairs:
            if (claimed_mime, detected_mime) == pair:
                is_match = True
                return is_match, is_suspicious, reason
        
        # Check if both are in the same category
        claimed_category = claimed_mime.split('/')[0]
        detected_category = detected_mime.split('/')[0]
        
        if claimed_category == detected_category:
            # Same category but different type - moderate suspicion
            is_suspicious = True
            reason = f"MIME mismatch within same category: claimed {claimed_mime} vs detected {detected_mime}"
        else:
            # Different categories - high suspicion
            is_suspicious = True
            reason = f"MIME category mismatch: claimed {claimed_mime} ({claimed_category}) vs detected {detected_mime} ({detected_category})"
        
        # Cross-validate with filetype library
        if filetype_result and filetype_result["mime"] == claimed_mime:
            # Filetype agrees with claimed, might be false positive from magic
            logger.warning(
                f"Conflicting detection: magic={detected_mime}, "
                f"claimed={claimed_mime}, filetype={filetype_result['mime']}"
            )
            # Reduce suspicion slightly but don't clear it
            reason += " (filetype library supports claimed MIME)"
        
        # Check for dangerous mismatches (trying to disguise executables)
        dangerous_detected = detected_mime in [
            "application/x-dosexec", "application/x-executable", 
            "application/x-elf", "application/x-msdownload",
            "application/x-mach-binary", "application/x-sharedlib"
        ]
        
        safe_claimed = claimed_mime.startswith(("image/", "text/", "video/", "audio/"))
        
        if dangerous_detected and safe_claimed:
            is_suspicious = True
            reason = f"CRITICAL: Executable disguised as {claimed_mime}"
        
        return is_match, is_suspicious, reason
    
    def _check_dangerous_patterns(
        self,
        filename: Optional[str],
        file_data: bytes,
        detected_mime: str
    ):
        """
        Check for dangerous file patterns and polyglot files
        
        Args:
            filename: Original filename
            file_data: Binary file data
            detected_mime: Detected MIME type
            
        Returns:
            Tuple of (is_suspicious, reason)
        """
        is_suspicious = False
        reasons = []
        
        if not filename:
            return is_suspicious, None
        
        # Check for double extensions (e.g., document.pdf.exe)
        filename_lower = filename.lower()
        parts = filename_lower.split('.')
        
        if len(parts) > 2:
            # Check for suspicious double extensions
            dangerous_extensions = ['.exe', '.bat', '.cmd', '.com', '.scr', '.vbs', 
                                   '.js', '.jar', '.ps1', '.msi', '.dll', '.sys']
            safe_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.jpg', 
                             '.jpeg', '.png', '.gif', '.txt', '.zip']
            
            # Check if penultimate extension looks safe but final is dangerous
            if len(parts) >= 3:
                penultimate_ext = '.' + parts[-2]
                final_ext = '.' + parts[-1]
                
                if penultimate_ext in safe_extensions and final_ext in dangerous_extensions:
                    is_suspicious = True
                    reasons.append(f"Double extension detected: {penultimate_ext}{final_ext}")
        
        # Check for null bytes in filename (path traversal attempts)
        if '\x00' in filename or '%00' in filename:
            is_suspicious = True
            reasons.append("Null byte in filename (path traversal attempt)")
        
        # Check for path traversal patterns
        if '../' in filename or '..\\' in filename:
            is_suspicious = True
            reasons.append("Path traversal pattern in filename")
        
        # Check for polyglot files (multiple valid file signatures)
        signatures_found = []
        
        # Common file signatures to check
        polyglot_signatures = [
            (b'%PDF-', "PDF"),
            (b'\xff\xd8\xff', "JPEG"),
            (b'\x89PNG\r\n\x1a\n', "PNG"),
            (b'GIF8', "GIF"),
            (b'PK\x03\x04', "ZIP"),
            (b'MZ', "PE/EXE"),
            (b'\x7fELF', "ELF"),
            (b'<html', "HTML", 0, 100),  # Check first 100 bytes
            (b'<?xml', "XML", 0, 100),
            (b'<svg', "SVG", 0, 100),
        ]
        
        for sig_data in polyglot_signatures:
            if len(sig_data) == 2:
                sig, name = sig_data
                offset = 0
                search_length = len(file_data)
            else:
                sig, name, offset, search_length = sig_data
            
            # Check at start of file
            if len(file_data) >= offset + len(sig):
                if file_data[offset:offset+len(sig)] == sig:
                    signatures_found.append(name)
            
            # Also search for signature elsewhere in file (polyglot detection)
            if offset == 0 and len(file_data) > 512:
                search_region = file_data[512:min(len(file_data), 8192)]
                if sig in search_region:
                    if name not in signatures_found:
                        signatures_found.append(f"{name} (embedded)")
                        is_suspicious = True
                        reasons.append(f"Embedded {name} signature found (possible polyglot)")
        
        # Check if multiple signatures detected at file start
        start_signatures = [s for s in signatures_found if "(embedded)" not in s]
        if len(start_signatures) > 1:
            is_suspicious = True
            reasons.append(f"Multiple file signatures detected: {', '.join(start_signatures)}")
        
        # Check for script tags in non-HTML files
        if detected_mime not in ["text/html", "application/xhtml+xml"]:
            dangerous_patterns = [
                b'<script',
                b'javascript:',
                b'onerror=',
                b'onclick=',
                b'onload=',
                b'eval(',
            ]
            
            for pattern in dangerous_patterns:
                if pattern in file_data[:8192]:  # Check first 8KB
                    is_suspicious = True
                    reasons.append(f"Suspicious pattern '{pattern.decode('latin-1')}' in non-HTML file")
                    break
        
        # Check for executable content in images
        if detected_mime.startswith("image/"):
            exe_markers = [b'MZ', b'\x7fELF', b'<?php']
            for marker in exe_markers:
                if marker in file_data[512:]:  # Skip header
                    is_suspicious = True
                    reasons.append("Executable code embedded in image file")
                    break
        
        # Check for zip bomb indicators in archive files
        if detected_mime in ["application/zip", "application/x-rar-compressed"]:
            # Check for suspicious compression ratio
            if detected_mime == "application/zip":
                try:
                    with zipfile.ZipFile(io.BytesIO(file_data), 'r') as zf:
                        compressed_size = len(file_data)
                        uncompressed_size = sum(info.file_size for info in zf.filelist)
                        
                        if uncompressed_size > 0:
                            ratio = uncompressed_size / compressed_size
                            if ratio > 1000:  # More than 1000x compression
                                is_suspicious = True
                                reasons.append(f"Suspicious compression ratio: {ratio:.0f}x (possible zip bomb)")
                except:
                    pass  # Ignore zip parsing errors here
        
        reason = " | ".join(reasons) if reasons else None
        return is_suspicious, reason
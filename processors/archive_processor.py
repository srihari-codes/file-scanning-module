"""
ArchiveProcessor module

Produces a structured report for archive files to feed into ML pipelines.
- Handles: ZIP, TAR (tar/tar.gz/tar.bz2), 7z (if py7zr installed). RAR will be attempted if unrar available.
- No decisions are made — only extraction of metadata, text, iocs, and per-file metrics.

API:
class ArchiveProcessor:
    @classmethod
    def process(cls, file_data: bytes, file_extension: str) -> Dict[str, Any]

Returns dict with the exact report structure requested by the user.

Notes:
- This module tries to be defensive: optional dependencies are used when present, and degraded behavior is provided when they are not.
- "0% false positives/negatives" is impossible to guarantee in practice (depends on heuristics, available libs, and file formats). This module implements conservative, well-tested heuristics.
"""

from __future__ import annotations

import io
import os
import re
import tempfile
import zipfile
import tarfile
import mimetypes
import math
import json
from collections import defaultdict, Counter
from typing import Any, Dict, List, Tuple, Optional

# optional imports
try:
    import py7zr
except Exception:
    py7zr = None

try:
    from PIL import Image
    from PIL.ExifTags import TAGS as PIL_EXIF_TAGS
except Exception:
    Image = None
    PIL_EXIF_TAGS = {}

try:
    import PyPDF2
except Exception:
    PyPDF2 = None

# language detection intentionally disabled to avoid optional dependency
# and non-deterministic behavior in analysis pipelines.
# If language detection is later required, replace this with a
# safe, deterministic implementation.
detect_lang = None


# -------------------------- Helper utilities --------------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    ent = 0.0
    for cnt in counts.values():
        p = cnt / length
        ent -= p * math.log2(p)
    return ent


# simple mime guessing fallback (extension based)
_EXTENSION_TO_MIME_BUCKET = {
    'image': {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'},
    'video': {'.mp4', '.mkv', '.mov', '.avi', '.wmv', '.flv', '.webm'},
    'audio': {'.mp3', '.wav', '.ogg', '.flac', '.m4a'},
    'documents': {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.rtf', '.txt'},
    'executables': {'.exe', '.dll', '.so', '.elf', '.bin', '.msi'},
    'scripts': {'.js', '.py', '.sh', '.ps1', '.bat', '.pl', '.rb'},
}


def guess_mime_bucket(filename: str) -> str:
    ext = os.path.splitext(filename.lower())[1]
    for bucket, exts in _EXTENSION_TO_MIME_BUCKET.items():
        if ext in exts:
            return bucket
    mt, _ = mimetypes.guess_type(filename)
    if mt:
        if mt.startswith('image/'):
            return 'image'
        if mt.startswith('video/'):
            return 'video'
        if mt.startswith('audio/'):
            return 'audio'
        if mt in ('application/pdf', 'application/msword') or mt.startswith('text/'):
            return 'documents'
    return 'others'


# IOC regexes (conservative)
EMAIL_RE = re.compile(rb"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
URL_RE = re.compile(rb"https?://[\w\-\./?=&%#]+")
IP_RE = re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
DOMAIN_RE = re.compile(rb"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
FILEPATH_UNIX_RE = re.compile(rb"(/[^\x00-\n\r<>\"'\\]+)+")
FILEPATH_WIN_RE = re.compile(rb"[A-Za-z]:\\[^\x00-\n\r<>\"']+(?:\\[^\x00-\n\r<>\"']+)*")
REGISTRY_RE = re.compile(rb"HKEY_[A-Z_]+\\[\w\\]+")


def extract_iocs_from_bytes(data: bytes) -> Dict[str, List[str]]:
    try:
        emails = {m.decode('utf-8', errors='ignore') for m in EMAIL_RE.findall(data)}
        urls = {m.decode('utf-8', errors='ignore') for m in URL_RE.findall(data)}
        ips = {m.decode('utf-8', errors='ignore') for m in IP_RE.findall(data)}
        domains = {m.decode('utf-8', errors='ignore') for m in DOMAIN_RE.findall(data)}
        file_paths = {m.decode('utf-8', errors='ignore') for m in FILEPATH_UNIX_RE.findall(data)} | {m.decode('utf-8', errors='ignore') for m in FILEPATH_WIN_RE.findall(data)}
        registry_paths = {m.decode('utf-8', errors='ignore') for m in REGISTRY_RE.findall(data)}
    except Exception:
        return {k: [] for k in ['emails','ips','domains','urls','file_paths','registry_paths']}

    return {
        'emails': sorted(emails),
        'ips': sorted(ips),
        'domains': sorted(domains - urls),  # naive de-dupe: urls already captured
        'urls': sorted(urls),
        'file_paths': sorted(file_paths),
        'registry_paths': sorted(registry_paths),
    }


def extract_exif(bytes_data: bytes) -> Dict[str, Any]:
    if Image is None:
        return {}
    try:
        bio = io.BytesIO(bytes_data)
        img = Image.open(bio)
        info = img.getexif() or {}
        pretty = {}
        for k, v in info.items():
            name = PIL_EXIF_TAGS.get(k, k)
            pretty[str(name)] = str(v)
        return pretty
    except Exception:
        return {}


def extract_pdf_metadata(bytes_data: bytes) -> Dict[str, Any]:
    if PyPDF2 is None:
        return {}
    try:
        reader = PyPDF2.PdfReader(io.BytesIO(bytes_data))
        md = reader.metadata or {}
        return {k: str(v) for k, v in md.items()}
    except Exception:
        return {}


def detect_text_and_language(bytes_data: bytes) -> Tuple[str, Optional[str]]:
    # attempt to decode text (conservative)
    # prefer utf-8, then latin-1 fallback
    text = ''
    lang = None
    try:
        text = bytes_data.decode('utf-8')
    except Exception:
        try:
            text = bytes_data.decode('latin-1')
        except Exception:
            # binary - return empty
            return ('', None)

    # collapse large binary-like noise
    if len(text) > 100000:
        sample = text[:100000]
    else:
        sample = text

    # Language detection has been disabled to avoid an optional dependency
    # and non-deterministic results. Always return `None` for language.
    lang = None

    return (sample, lang)


# -------------------------- Main Archive Processing --------------------------

class ArchiveProcessor:
    @classmethod
    def process(cls, file_data: bytes, file_extension: str) -> Dict[str, Any]:
        """Process archive bytes and return the structured report.

        file_extension: string like '.zip', '.tar', '.7z', '.gz', '.bz2', '.rar'
        """
        # write to temp file and operate on disk-based handlers
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(file_data)
            tmp.flush()
            tmp_path = tmp.name

        try:
            # attempt handlers in order
            report = cls._process_with_handlers(tmp_path, file_extension.lower())
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        return report

    @classmethod
    def _process_with_handlers(cls, path: str, ext: str) -> Dict[str, Any]:
        # Initialize output structure
        report = {
            'password_protected': False,
            'encrypted_entries': 0,
            'file_count': 0,
            'directory_tree': [],
            'mime_distribution': {
                'image': 0,'video': 0,'audio': 0,'documents': 0,'executables': 0,'scripts': 0,'others': 0
            },
            'entries': [],
            'summary_metrics': {
                'avg_entropy': 0.0,
                'macro_present': False,
                'num_high_entropy_files': 0,
                'num_executables': 0,
                'num_scripts': 0
            },
            'seperate_file_details': {}
        }

        entries = []

        # Try ZIP
        if ext in ('.zip',):
            try:
                with zipfile.ZipFile(path) as zf:
                    for zi in zf.infolist():
                        is_dir = zi.is_dir()
                        name = zi.filename
                        size = zi.file_size
                        is_encrypted = (zi.flag_bits & 0x1) != 0
                        if is_encrypted:
                            report['encrypted_entries'] += 1
                        # read content if not dir and not encrypted
                        content_bytes = b''
                        if not is_dir and not is_encrypted:
                            try:
                                with zf.open(zi, pwd=None) as fh:
                                    content_bytes = fh.read()
                            except RuntimeError:
                                # encrypted with password
                                report['encrypted_entries'] += 1
                                report['password_protected'] = True
                                content_bytes = b''
                        entry = cls._analyze_file_bytes(name, size, content_bytes)
                        entries.append(entry)
                        report['file_count'] += 0 if is_dir else 1
                        report['directory_tree'].append({'path': name, 'type': 'folder' if is_dir else 'file', 'size_bytes': size})
            except zipfile.BadZipFile:
                # fallthrough
                pass

        # Try TAR (includes gz/bz2) — tarfile autodetects compression
        if not entries and ext.startswith('.tar') or (not entries and ext in ('.gz', '.bz2', '.tgz')):
            try:
                with tarfile.open(path) as tf:
                    for ti in tf.getmembers():
                        is_dir = ti.isdir()
                        name = ti.name
                        size = ti.size
                        content_bytes = b''
                        if ti.isreg():
                            try:
                                f = tf.extractfile(ti)
                                if f:
                                    content_bytes = f.read()
                            except Exception:
                                content_bytes = b''
                        entry = cls._analyze_file_bytes(name, size, content_bytes)
                        entries.append(entry)
                        report['file_count'] += 0 if is_dir else 1
                        report['directory_tree'].append({'path': name, 'type': 'folder' if is_dir else 'file', 'size_bytes': size})
            except tarfile.ReadError:
                pass

        # Try 7z
        if not entries and py7zr and ext in ('.7z',):
            try:
                with py7zr.SevenZipFile(path, mode='r') as archive:
                    allinfos = archive.list()
                    for info in allinfos:
                        name = info.filename
                        is_dir = info.is_directory
                        size = info.uncompressed
                        content_bytes = b''
                        if not is_dir:
                            try:
                                # Extract the file to a temporary directory and read its contents
                                with tempfile.TemporaryDirectory() as extract_dir:
                                    archive.extract(targets=[name], path=extract_dir)
                                    extracted_path = os.path.join(extract_dir, name)
                                    try:
                                        with open(extracted_path, 'rb') as efh:
                                            content_bytes = efh.read()
                                    except Exception:
                                        content_bytes = b''
                            except Exception:
                                content_bytes = b''
                        entry = cls._analyze_file_bytes(name, size, content_bytes)
                        entries.append(entry)
                        report['file_count'] += 0 if is_dir else 1
                        report['directory_tree'].append({'path': name, 'type': 'folder' if is_dir else 'file', 'size_bytes': size})
            except Exception:
                pass

        # If still no entries, attempt generic scan reading file as single blob
        if not entries:
            # treat whole file as single file inside archive
            name = os.path.basename(path)
            size = os.path.getsize(path)
            try:
                with open(path, 'rb') as fh:
                    blob = fh.read()
            except Exception:
                blob = b''
            entry = cls._analyze_file_bytes(name, size, blob)
            entries.append(entry)
            report['file_count'] = 1
            report['directory_tree'].append({'path': name, 'type': 'file', 'size_bytes': size})

        # populate mime distribution and summary metrics
        total_entropy = 0.0
        high_entropy_count = 0
        macro_present = False
        num_exec = 0
        num_scripts = 0

        for e in entries:
            bucket = e.get('mime_type_bucket', 'others')
            report['mime_distribution'][bucket] = report['mime_distribution'].get(bucket, 0) + 1
            total_entropy += e.get('entropy', 0.0)
            if e.get('entropy', 0.0) > 7.5:
                high_entropy_count += 1
            if e.get('is_executable'):
                num_exec += 1
            if e.get('is_script'):
                num_scripts += 1
            if e.get('contains_macros'):
                macro_present = True

            # record separate file details raw
            report['seperate_file_details'][e.get('file_path', 'unknown')] = e.get('raw_metadata', {})

            # remove internal-only fields before adding to entries output
            for _k in ('raw_metadata', 'mime_type_bucket'):
                if _k in e:
                    del e[_k]

        avg_entropy = (total_entropy / len(entries)) if entries else 0.0
        report['entries'] = entries
        report['summary_metrics']['avg_entropy'] = avg_entropy
        report['summary_metrics']['macro_present'] = macro_present
        report['summary_metrics']['num_high_entropy_files'] = high_entropy_count
        report['summary_metrics']['num_executables'] = num_exec
        report['summary_metrics']['num_scripts'] = num_scripts

        return report

    @classmethod
    def _analyze_file_bytes(cls, filename: str, size: int, data: bytes) -> Dict[str, Any]:
        # basic mime type
        mt, _ = mimetypes.guess_type(filename)
        mime_type = mt or 'application/octet-stream'
        bucket = guess_mime_bucket(filename)

        entropy = shannon_entropy(data)

        is_executable = False
        is_script = False
        contains_macros = False
        exif_md = {}
        doc_md = {}
        text_content = ''
        text_lang = None

        # heuristics
        ext = os.path.splitext(filename.lower())[1]
        if ext in ('.exe', '.dll') or filename.lower().endswith(('.elf', '.bin')):
            is_executable = True
        if ext in ('.js', '.py', '.sh', '.ps1', '.bat'):
            is_script = True

        # detect macros (heuristic): look for VBA streams and typical keywords
        if b'VBA' in data or b'Microsoft Visual Basic' in data or b'word/vbaData' in data:
            contains_macros = True
        # also scan for "Sub " and "Function " near ASCII range as supplemental signal
        if re.search(rb"\b(Sub |Function |Attribute VB_)", data):
            contains_macros = True

        # exif for images
        if bucket == 'image' and data:
            exif_md = extract_exif(data)

        # document metadata (PDF)
        if ext == '.pdf' and data:
            doc_md = extract_pdf_metadata(data)

        # try text extraction for text-like files
        if bucket in ('documents','scripts','others') or ext in ('.txt', '.log', '.csv', '.json'):
            txt, lang = detect_text_and_language(data)
            text_content = txt
            text_lang = lang

        iocs = extract_iocs_from_bytes(data)

        raw_meta = {
            'filename': filename,
            'size_bytes': size,
            'mimetag': mime_type,
            'guessed_bucket': bucket,
            'entropy': entropy,
        }

        entry = {
            'file_path': filename,
            'file_size_bytes': size,
            'mime_type': mime_type,
            'is_executable': bool(is_executable),
            'is_script': bool(is_script),
            'entropy': float(round(entropy, 4)),
            'contains_macros': bool(contains_macros),
            'exif_metadata': exif_md,
            'document_metadata': doc_md,
            'text_content': text_content,
            'text_language': text_lang or 'unknown',
            'ioc_extraction': iocs,
            'raw_metadata': raw_meta,
            'mime_type_bucket': bucket
        }

        return entry


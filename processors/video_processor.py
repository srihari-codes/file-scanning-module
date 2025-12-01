from __future__ import annotations
import os
import io
import re
import sys
import json
import math
import uuid
import time
import shutil
import hashlib
import tempfile
import logging
import subprocess
from typing import Optional, List, Dict, Any, Tuple, Sequence
from dataclasses import dataclass, asdict


# third-party imports (no safety nets)

import cv2
import numpy as np
import ffmpeg
import pytesseract
import easyocr
from nudenet import NudeDetector  # v3.x
from pyzbar.pyzbar import decode as pyzbar_decode
from ultralytics.models.yolo import YOLO  # type: ignore

import whisper  # openai-whisper
import torch

# Logging config
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("video_processor")

# ---------- Helpers ----------

def _write_temp_file(data: bytes, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    with open(path, "wb") as f:
        f.write(data)
    return path


def _sha256_hex(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_probe(path: str) -> Dict[str, Any]:
    """Call ffprobe subprocess to get video metadata as JSON."""
    try:
        cmd = [
            "ffprobe",
            "-v",
            "error",
            "-show_format",
            "-show_streams",
            "-of",
            "json",
            path,
        ]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return json.loads(out)
    except Exception as e:
        logger.warning("ffprobe failed: %s", e)
        return {}


# ---------- Data classes for internal use ----------
@dataclass
class ObjectDetection:
    label: str
    confidence: float


@dataclass
class FaceEmbedding:
    embedding_vector: List[float]


# ---------- Main class ----------
class VideoProcessor:
    """A modular video/image processor.

    All methods are intentionally single-responsibility so you may replace or extend
    any detector with your preferred library or model.
    """

    # configurable defaults
    SAMPLE_INTERVAL_SEC = 2.0
    OBJECT_CONFIDENCE_THRESHOLD = 0.35
    OCR_CONFIDENCE_THRESHOLD = 0.3
    FACE_TOLERANCE = 0.6  # for face matching (not used here since no identification)

    @classmethod
    def process(cls, file_data: bytes, file_extension: str) -> Dict[str, Any]:
        _debug_check_helpers()
        """Entry point. Accepts raw bytes of a video file and its extension (e.g. '.mp4').
        Returns JSON-like dict matching the required master structure.
        """
        tmp_video = _write_temp_file(file_data, suffix=file_extension)
        try:
            nude_detector = NudeDetector()

            metadata = cls.extract_file_metadata(tmp_video)
            video_props = cls.extract_video_properties(tmp_video)

            # sample frames
            interval = cls.SAMPLE_INTERVAL_SEC
            frames = list(cls.sample_frames(tmp_video, interval))

            frame_analysis: List[Dict[str, Any]] = []
            object_detector = cls._build_object_detector()
            scene_detector = cls._build_scene_detector()
            ocr_reader = cls._build_ocr_reader()

            for ts, frame in frames:
                objects = cls.detect_objects(frame, object_detector)
                scene_type = cls.detect_scenes(frame, scene_detector)
                ocr_text = cls.extract_ocr(frame, ocr_reader)
                faces = cls.extract_faces(frame)
                qr_data = cls.decode_qr(frame)
                motion_score = cls._motion_score_for_frame(frame)

                # Nudity detection
                # Save frame as a temporary image file
                import tempfile
                import cv2
                with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp_img:
                    cv2.imwrite(tmp_img.name, frame)
                    nudity_result = nude_detector.detect(tmp_img.name)
                os.unlink(tmp_img.name)  # Clean up temp file

                nudity_score = max((r.get('score', 0.0) for r in nudity_result), default=0.0)
                nudity_labels = list(set(r.get('class', '') for r in nudity_result if 'class' in r))

                frame_analysis.append(
                    {
                        "timestamp": round(ts, 2),
                        "objects": [asdict(x) for x in objects],
                        "faces": [asdict(f) for f in faces],
                        "ocr_text": ocr_text or "",
                        "qr_codes_decoded": qr_data,
                        "scene_type": scene_type or "unknown",
                        "motion_score": round(float(motion_score), 4),
                        "nudity_score": round(float(nudity_score), 4),
                        "nudity_labels": nudity_labels,
                    }
                )

            # audio
            audio_path = cls.extract_audio(tmp_video)
            transcript, languages, speakers = cls.speech_to_text(audio_path)
            keywords = cls.keyword_detection(transcript)

            # network indicators: parse OCR and transcript for urls, phones, ips
            network_indicators = cls._extract_network_indicators_from_text([f["ocr_text"] for f in frame_analysis], transcript, frame_analysis)

            # global summary
            num_people = cls._count_label_in_frames(frame_analysis, "person")
            num_faces = sum(len(f["faces"]) for f in frame_analysis)
            dominant_scenes = cls._dominant_scene_types(frame_analysis)

            timeline = cls.event_timeline_builder(frame_analysis, transcript, keywords)

            report = {
                "metadata": {
                    "filename": os.path.basename(tmp_video),
                    "format": video_props.get("format_name", ""),
                    "size_bytes": os.path.getsize(tmp_video),
                    "duration_sec": float(video_props.get("duration", 0)),
                    "resolution": f"{video_props.get('width', '')}x{video_props.get('height', '')}",
                    "fps": float(video_props.get("fps", 0)),
                    "bitrate_kbps": int(float(video_props.get("bit_rate", 0)) / 1000) if video_props.get("bit_rate") else 0,
                    "creation_time": video_props.get("creation_time", ""),
                    "device_info": {
                        "make": video_props.get("device_make", ""),
                        "model": video_props.get("device_model", ""),
                        "gps": video_props.get("gps", None),
                    },
                },
                "global_summary": {
                    "num_people_detected": num_people,
                    "num_faces_detected": num_faces,
                    "languages_detected": languages or [],
                    "dominant_scene_types": dominant_scenes,
                    "suspicion_score_raw": None,
                    "keywords_detected": keywords,
                },
                "frame_analysis": frame_analysis,
                "audio_analysis": {
                    "transcript": transcript or "",
                    "language": languages or [],
                    "speakers": speakers or [],
                    "keywords_detected": [
                        {"word": k[0], "timestamp": k[1]} for k in keywords
                    ],
                    "tone_analysis": cls._tone_analysis_from_transcript(transcript),
                },
                "network_indicators": network_indicators,
                "timeline": timeline,
            }

            return report
        finally:
            try:
                os.remove(tmp_video)
            except Exception:
                pass

    # ---------------- Individual functions ----------------

    @classmethod
    def extract_file_metadata(cls, path: str) -> Dict[str, Any]:
        """Pulls forensic metadata + hashes. Returns a dict (partial used later).
        Single responsibility: metadata only.
        """
        md = {}
        md["sha256"] = _sha256_hex(path)
        # try to get file system timestamps
        try:
            st = os.stat(path)
            md["created_at"] = time.ctime(st.st_ctime)
            md["modified_at"] = time.ctime(st.st_mtime)
        except Exception:
            md["created_at"] = md["modified_at"] = ""
        return md

    @classmethod
    def extract_video_properties(cls, path: str) -> Dict[str, Any]:
        """Resolves resolution, fps, duration, codecs, creation time, device info (best-effort).
        Single responsibility: probe and return normalized properties.
        """
        probe = _safe_probe(path)
        props: Dict[str, Any] = {}
        # parse
        fmt = probe.get("format", {})
        props["format_name"] = fmt.get("format_name") if isinstance(fmt, dict) else ""
        duration_val = fmt.get("duration")
        props["duration"] = float(duration_val) if duration_val is not None else 0
        props["bit_rate"] = fmt.get("bit_rate")

        # streams
        width = height = fps = 0
        for s in probe.get("streams", []) if probe else []:
            if s.get("codec_type") == "video":
                width = s.get("width")
                height = s.get("height")
                # fps calculation
                if s.get("r_frame_rate") and s.get("r_frame_rate") != "0/0":
                    try:
                        num, den = s.get("r_frame_rate").split("/")
                        fps = float(num) / float(den)
                    except Exception:
                        fps = 0
                # codec
                props["video_codec"] = s.get("codec_name")
            if s.get("codec_type") == "audio":
                props["audio_codec"] = s.get("codec_name")

        props["width"] = width
        props["height"] = height
        props["fps"] = fps

        # try to extract creation_time and device tags
        tags = fmt.get("tags") if fmt else {}
        if tags:
            props["creation_time"] = tags.get("creation_time") or tags.get("com.apple.quicktime.creationdate") or ""
            props["device_make"] = tags.get("encoder", "")
            props["device_model"] = tags.get("com.apple.quicktime.model", "")
            # gps data often not in container tags — left as None
            props["gps"] = None
        else:
            props["creation_time"] = ""
            props["device_make"] = ""
            props["device_model"] = ""
            props["gps"] = None

        return props

    @classmethod
    def sample_frames(cls, path: str, interval_seconds: Optional[float] = None):
        """Generator yielding (timestamp_sec, frame_bgr_numpy)
        Uses OpenCV VideoCapture. Single responsibility: sampling only.
        """
        if interval_seconds is None:
            interval_seconds = cls.SAMPLE_INTERVAL_SEC
        if cv2 is None:
            raise RuntimeError("OpenCV is required for sampling frames.")

        cap = cv2.VideoCapture(path)
        if not cap.isOpened():
            raise RuntimeError("Cannot open video for sampling")

        fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        duration = total_frames / fps if fps else 0

        t = 0.0
        while t < duration:
            frame_no = int(t * fps)
            cap.set(cv2.CAP_PROP_POS_FRAMES, frame_no)
            ret, frame = cap.read()
            if not ret:
                break
            yield (t, frame)
            t += interval_seconds
        cap.release()

    @classmethod
    def _build_object_detector(cls):
        """Factory for object detector. Returns a callable detector(frame)->List[ObjectDetection]
        Single responsibility: build model only.
        """
        if YOLO is not None:
            try:
                # use a common yolov8n or yolov8s if available — user can change path to custom weights
                model_path = os.path.join(os.path.dirname(__file__), "..", "helpers", "yolov8n.pt")
                model_path = os.path.abspath(model_path)
                device = "cuda" if torch.cuda.is_available() else "cpu"
                model = YOLO(model_path)
                model.to(device)
                def detect(frame):
                    results = model(frame, imgsz=640, device=device)
                    objects = []
                    for r in results:
                        for box in r.boxes:
                            conf = float(box.conf[0])
                            if conf < cls.OBJECT_CONFIDENCE_THRESHOLD:
                                continue
                            label_idx = int(box.cls[0])
                            name = model.names[label_idx] if hasattr(model, 'names') else str(label_idx)
                            objects.append(ObjectDetection(label=name, confidence=round(conf, 3)))
                    return objects
                return detect
            except Exception as e:
                logger.warning("YOLO model build failed: %s", e)
        def no_detector(frame):
            return []
        return no_detector

    @classmethod
    def detect_objects(cls, frame: Any, detector_callable=None) -> List[ObjectDetection]:
        """Single responsibility: run detector and normalise results.
        Detector callable should accept BGR numpy array and return list of ObjectDetection.
        """
        if detector_callable is None:
            detector_callable = cls._build_object_detector()
        try:
            results = detector_callable(frame)
            # enforce structure
            out = []
            for r in results:
                if isinstance(r, ObjectDetection):
                    out.append(r)
                elif isinstance(r, dict):
                    out.append(ObjectDetection(label=r.get('label', 'unknown'), confidence=float(r.get('confidence', 0))))
            # simple dedup: keep highest confidence per label
            best = {}
            for o in out:
                if o.label not in best or o.confidence > best[o.label].confidence:
                    best[o.label] = o
            return list(best.values())
        except Exception as e:
            logger.exception("object detection failed: %s", e)
            return []

    @classmethod
    def _build_scene_detector(cls):
        """Factory for scene detector. Returns callable(frame)->str
        We provide a heuristic fallback: CLIP or Places would be ideal; but for portability we use
        a tiny color + texture heuristic with optional EasyOCR cues.
        Single responsibility: build model only.
        """
        # Simple heuristic detector
        def heuristic(frame):
            try:
                h, w = frame.shape[:2]
                # center crop
                c = frame[h//4: h*3//4, w//4: w*3//4]
                avg = np.mean(c)
                # if very bright and lots of green = outdoors
                green_mean = np.mean(c[:, :, 1]) if c is not None else 0
                if green_mean > 90 and avg > 80:
                    return "outdoor"
                # if text present (OCR), likely indoor/office/bedroom
                # but we won't call OCR here for speed
                return "indoor"
            except Exception:
                return "unknown"

        return heuristic

    @classmethod
    def detect_scenes(cls, frame: Any, detector_callable=None) -> Optional[str]:
        if detector_callable is None:
            detector_callable = cls._build_scene_detector()
        try:
            return detector_callable(frame)
        except Exception as e:
            logger.exception("scene detection failed: %s", e)
            return "unknown"

    @classmethod
    def _build_ocr_reader(cls):
        """Return an OCR function (frame)->string. Tries to ensemble pytesseract + easyocr.
        Single responsibility: build model only.
        """
        readers = []
        if pytesseract is not None:
            def tesseract_reader(frame):
                try:
                    img = frame
                    img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
                    txt = pytesseract.image_to_string(img_rgb)
                    return txt
                except Exception:
                    return ""
            readers.append(tesseract_reader)
        if easyocr is not None:
            try:
                    er = easyocr.Reader(['en'], gpu=True)
                    from typing import List, Any
                    def easy_reader(frame) -> str:
                        try:
                            img_gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                            res: Sequence[Any] = er.readtext(img_gray)
                            return " ".join([
                                r[1] for r in res
                                if isinstance(r, (list, tuple)) and len(r) > 1
                            ])
                        except Exception:
                            return ""
                    readers.append(easy_reader)
            except Exception:
                pass

        if not readers:
            def null_ocr(frame):
                return ""
            return null_ocr

        def ensemble(frame):
            texts = []
            for r in readers:
                try:
                    t = r(frame)
                    if t:
                        texts.append(t.strip())
                except Exception:
                    continue
            # simple merge: choose longest non-empty, and add dedup
            texts = [t for t in texts if t]
            if not texts:
                return ""
            texts = sorted(texts, key=lambda s: len(s), reverse=True)
            return texts[0]

        return ensemble

    @classmethod
    def extract_ocr(cls, frame: Any, ocr_callable=None) -> str:
        if ocr_callable is None:
            ocr_callable = cls._build_ocr_reader()
        try:
            txt = ocr_callable(frame)
            return txt.strip() if txt else ""
        except Exception as e:
            logger.exception("OCR failed: %s", e)
            return ""

    @classmethod
    def extract_faces(cls, frame: Any) -> List[FaceEmbedding]:
        """Detect faces using OpenCV DNN face detector. Returns bounding boxes only (no embeddings)."""
        helpers_dir = os.path.join(os.path.dirname(__file__), "..", "helpers")
        proto_path = os.path.join(helpers_dir, "deploy.prototxt")
        model_path = os.path.join(helpers_dir, "res10_300x300_ssd_iter_140000.caffemodel")
        if not os.path.exists(proto_path) or not os.path.exists(model_path):
            logger.error("Face detector model files not found. Please download deploy.prototxt and res10_300x300_ssd_iter_140000.caffemodel.")
            return []
        net = cv2.dnn.readNetFromCaffe(proto_path, model_path)
        # Do not force backend/target; let OpenCV decide
        h, w = frame.shape[:2]
        blob = cv2.dnn.blobFromImage(cv2.resize(frame, (300, 300)), 1.0, (300, 300), (104.0, 177.0, 123.0))
        net.setInput(blob)
        detections = net.forward()
        out = []
        for i in range(0, detections.shape[2]):
            confidence = detections[0, 0, i, 2]
            if confidence > 0.5:
                box = detections[0, 0, i, 3:7] * np.array([w, h, w, h])
                (startX, startY, endX, endY) = box.astype("int")
                out.append(FaceEmbedding(embedding_vector=[float(startX), float(startY), float(endX), float(endY), float(confidence)]))
        return out

    @classmethod
    def extract_audio(cls, path: str) -> Optional[str]:
        """Extract audio to a WAV file and return path. Single responsibility: audio extraction only.
        """
        out_wav = tempfile.mktemp(suffix=".wav")
        # prefer ffmpeg
        try:
            cmd = [
                "ffmpeg",
                "-y",
                "-i",
                path,
                "-vn",
                "-acodec",
                "pcm_s16le",
                "-ar",
                "16000",
                "-ac",
                "1",
                out_wav,
            ]
            subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            return out_wav
        except Exception as e:
            logger.warning("ffmpeg audio extract failed: %s", e)
            return None

    @classmethod
    def speech_to_text(cls, audio_path: Optional[str]) -> Tuple[str, List[str], List[Dict[str, Any]]]:
        """Speech to text. Returns (transcript, [langs], speakers list).
        Single responsibility: transcription only.
        """
        if not audio_path:
            return "", [], []
        try:
            device = "cuda" if torch.cuda.is_available() else "cpu"
            model = whisper.load_model("small", device=device)
            res = model.transcribe(audio_path)
            text_val = res.get("text", "")
            if isinstance(text_val, str):
                text = text_val.strip()
            elif isinstance(text_val, list):
                text = " ".join(str(seg) for seg in text_val).strip()
            else:
                text = str(text_val).strip()
            language_raw = res.get("language")
            if isinstance(language_raw, str):
                language = [language_raw]
            elif isinstance(language_raw, list):
                language = [str(l) for l in language_raw if isinstance(l, str)]
            elif language_raw is not None:
                language = [str(language_raw)]
            else:
                language = []
            segments = res.get("segments", [])
            last_end = segments[-1]["end"] if segments and isinstance(segments[-1], dict) and "end" in segments[-1] else 0.0
            speakers = [{"speaker": 1, "start": 0.0, "end": last_end}]
            return text, language, speakers
        except Exception as e:
            logger.warning("whisper transcription failed: %s", e)
            return "", [], []

    @classmethod
    def keyword_detection(cls, transcript: str, keyword_list: Optional[List[str]] = None) -> List[Tuple[str, float]]:
        """Search for keywords in transcript and return list of (word, timestamp)
        Single responsibility: detection of keywords only.
        Uses simple regex + boundaries. Timestamp estimation is naive (maps word index -> time) if transcript has no segments.
        """
        if not transcript:
            return []
        if keyword_list is None:
            keyword_list = ["otp", "password", "login", "pin", "bank", "account", "transfer"]
        text = transcript.lower()
        found = []
        for kw in keyword_list:
            for m in re.finditer(r"\b" + re.escape(kw.lower()) + r"\b", text):
                # estimate timestamp
                # naive: position/length * total_duration_unknown => put -1 if unknown
                found.append((kw, -1.0))
        return found

    @classmethod
    def decode_qr(cls, frame: Any) -> List[str]:
        if pyzbar_decode is None:
            return []
        try:
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            res = pyzbar_decode(rgb)
            out = []
            for r in res:
                try:
                    out.append(r.data.decode("utf-8"))
                except Exception:
                    out.append(r.data)
            return out
        except Exception as e:
            logger.exception("QR decode failed: %s", e)
            return []

    @classmethod
    def event_timeline_builder(cls, frame_analysis: List[Dict[str, Any]], transcript: str, keywords: List[Tuple[str, float]]) -> List[Dict[str, Any]]:
        """Create a simple second-wise chronological report using frame analysis and transcript keywords.
        Single responsibility: timeline building only.
        """
        events = []
        # from frames: detect scenes / objects per second
        for f in frame_analysis:
            sec = int(round(f["timestamp"]))
            # common event heuristics
            if any(o['label'] == 'person' for o in f['objects']):
                events.append({"second": sec, "event": "Person seen"})
            if 'bank' in (f.get('ocr_text') or '').lower():
                events.append({"second": sec, "event": "Bank app seen on screen"})
            if f.get('qr_codes_decoded'):
                events.append({"second": sec, "event": "QR code visible"})
        # from keywords
        for kw, ts in keywords:
            events.append({"second": int(ts) if ts >= 0 else -1, "event": f"Keyword spoken: {kw}"})
        # consolidate and sort
        events_sorted = sorted(events, key=lambda x: x['second'] if x['second'] >= 0 else 999999)
        return events_sorted

    # ---------------- Utility analysis functions ----------------

    @classmethod
    def _motion_score_for_frame(cls, frame: Any) -> float:
        """Very simple motion score using Laplacian variance (focus proxy) — placeholder for real optical flow."""
        try:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            return float(cv2.Laplacian(gray, cv2.CV_64F).var() / 1000.0)
        except Exception:
            return 0.0

    @classmethod
    def _extract_network_indicators_from_text(cls, ocr_texts: List[str], transcript: str, frame_analysis: List[Dict[str, Any]]) -> Dict[str, Any]:
        text_pool = "\n".join(ocr_texts + ([transcript] if transcript else []))
        urls = re.findall(r"https?://[\w\-\.\/%\?=&]+", text_pool)
        ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text_pool)
        phones = re.findall(r"\+?\d[\d\- ]{7,}\d", text_pool)
        qr_data = []
        for f in frame_analysis:
            qr_data.extend(f.get('qr_codes_decoded', []))
        return {"urls": urls, "ip_addresses": ips, "phone_numbers": phones, "qr_data": qr_data}

    @classmethod
    def _count_label_in_frames(cls, frames: List[Dict[str, Any]], label: str) -> int:
        cnt = 0
        for f in frames:
            for o in f.get('objects', []):
                if o.get('label') == label:
                    cnt += 1
        return cnt

    @classmethod
    def _dominant_scene_types(cls, frames: List[Dict[str, Any]]) -> List[str]:
        c = {}
        for f in frames:
            t = f.get('scene_type', 'unknown')
            c[t] = c.get(t, 0) + 1
        if not c:
            return []
        # return top 2
        items = sorted(c.items(), key=lambda kv: kv[1], reverse=True)
        return [items[0][0]] + ([items[1][0]] if len(items) > 1 else [])

    @classmethod
    def _tone_analysis_from_transcript(cls, transcript: str) -> Dict[str, float]:
        # naive tone analysis using keywords (placeholder for an ML model)
        if not transcript:
            return {"aggression": 0.0, "urgency": 0.0, "stress": 0.0}
        t = transcript.lower()
        urgency = 1.0 if any(x in t for x in ['now', 'immediately', 'quickly', 'urgent']) else 0.1
        aggression = 1.0 if any(x in t for x in ['shut up', 'idiot', 'stupid']) else 0.05
        stress = 0.8 if any(x in t for x in ['help', 'sos', 'panic']) else 0.2
        return {"aggression": round(aggression, 2), "urgency": round(urgency, 2), "stress": round(stress, 2)}

import os

def _debug_check_helpers():
    helpers_dir = os.path.join(os.path.dirname(__file__), "..", "helpers")
    yolov8_path = os.path.abspath(os.path.join(helpers_dir, "yolov8n.pt"))
    proto_path = os.path.abspath(os.path.join(helpers_dir, "deploy.prototxt"))
    caffemodel_path = os.path.abspath(os.path.join(helpers_dir, "res10_300x300_ssd_iter_140000.caffemodel"))
    print("YOLO weights:", yolov8_path, "Exists:", os.path.exists(yolov8_path))
    print("Face proto:", proto_path, "Exists:", os.path.exists(proto_path))
    print("Face caffemodel:", caffemodel_path, "Exists:", os.path.exists(caffemodel_path))

# Call this at the top of process() for debugging


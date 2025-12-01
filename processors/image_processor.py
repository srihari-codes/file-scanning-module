from __future__ import annotations

import io
import os
import sys
import math
import uuid
import json
import time
import hashlib
import logging
import statistics
from datetime import datetime, timezone
from typing import Optional, Tuple, List, Dict, Any

# Image & array processing
from PIL import Image, ImageOps, ImageFile, ExifTags
ImageFile.LOAD_TRUNCATED_IMAGES = True
import numpy as np

# Optional dependencies (NO SAFETY NETS - will fail loudly if missing)
import cv2
import piexif
import exifread
import pytesseract
from sklearn.cluster import KMeans
from skimage import filters, util, color
from skimage.measure import shannon_entropy
from skimage.restoration import estimate_sigma

# Face detection options - using OpenCV instead of face_recognition (more reliable on Windows)
face_recognition = None  # Deprecated - using cv2 for face detection instead

# NSFW detection: NudeNet v3.x
from nudenet import NudeDetector

# Object detection option (ultralytics/yolov8)
from ultralytics.models.yolo import YOLO  # type: ignore

# Embeddings (CLIP)
import torch
from PIL import Image as PILImage
from torchvision import transforms
from torchvision.models import vit_b_16

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _utc_iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _safe_int(v):
    try:
        return int(v)
    except Exception:
        return None


class ImageProcessor:
    VERSION = "1.0.0"

    @staticmethod
    def _hash_bytes(b: bytes, algo: str = "sha256") -> str:
        h = hashlib.new(algo)
        h.update(b)
        return h.hexdigest()

    @staticmethod
    def _load_image(file_data: bytes) -> Optional[Image.Image]:
        try:
            bio = io.BytesIO(file_data)
            img = Image.open(bio)
            img.load()
            return img
        except Exception as e:
            logger.debug("PIL open failed: %s", e)
            return None

    @staticmethod
    def _dominant_colors(img: Image.Image, n_colors: int = 5) -> Optional[List[Dict[str, Any]]]:
        try:
            arr = np.array(img.convert('RGB'))
            h, w, c = arr.shape
            pixels = arr.reshape(-1, 3).astype(float)
            if KMeans is None:
                # fallback: simple histogram-based mode
                pixels_tuple = [tuple(p) for p in pixels]
                counts = {}
                for p in pixels_tuple:
                    counts[p] = counts.get(p, 0) + 1
                most = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n_colors]
                total = len(pixels_tuple)
                return [{"rgb": [int(k[0]), int(k[1]), int(k[2])], "percent": v/total} for k, v in most]
            kmeans = KMeans(n_clusters=min(n_colors, len(pixels)))
            labels = kmeans.fit_predict(pixels)
            centers = kmeans.cluster_centers_.astype(int)
            out = []
            total = pixels.shape[0]
            for i, cval in enumerate(centers):
                percent = float(np.sum(labels == i)) / total
                out.append({"rgb": [int(cval[0]), int(cval[1]), int(cval[2])], "percent": percent})
            out = sorted(out, key=lambda x: x['percent'], reverse=True)
            return out
        except Exception as e:
            logger.debug("dominant color failed: %s", e)
            return None

    @staticmethod
    def _jpeg_quant_signature(img_bytes: bytes) -> Optional[str]:
        # crude attempt to parse quant tables for JPEGs; returns SHA256 of quant tables string
        try:
            # scan for DQT marker (0xFFDB)
            i = 0
            tables = []
            b = img_bytes
            while True:
                i = b.find(b"\xFF\xDB", i)
                if i == -1:
                    break
                # length bytes
                if i+4 > len(b):
                    break
                length = int.from_bytes(b[i+2:i+4], 'big')
                chunk = b[i+4:i+2+length]
                tables.append(chunk.hex())
                i += 2
            if not tables:
                return None
            s = "|".join(tables).encode('utf-8')
            return hashlib.sha256(s).hexdigest()
        except Exception as e:
            logger.debug("jpeg quant parse failed: %s", e)
            return None

    @staticmethod
    def _entropy(arr: np.ndarray) -> Optional[float]:
        try:
            return float(shannon_entropy(arr))
        except Exception as e:
            logger.debug("entropy failed: %s", e)
            return None

    @staticmethod
    def _edge_density_gray(gray: np.ndarray) -> Optional[float]:
        try:
            edges = cv2.Canny((gray*255).astype('uint8'), 100, 200)
            return float((edges>0).sum()) / edges.size
        except Exception as e:
            logger.debug("edge density failed: %s", e)
            return None

    @staticmethod
    def _blur_metric(gray: np.ndarray) -> Optional[Dict[str, float]]:
        """Calculate multiple blur metrics for validation."""
        try:
            gray_uint8 = (gray*255).astype('uint8')
            
            # Method 1: Laplacian variance (original)
            lap = cv2.Laplacian(gray_uint8, cv2.CV_64F)
            laplacian_var = float(lap.var())
            
            # Method 2: Tenengrad (gradient magnitude)
            sobelx = cv2.Sobel(gray_uint8, cv2.CV_64F, 1, 0, ksize=3)
            sobely = cv2.Sobel(gray_uint8, cv2.CV_64F, 0, 1, ksize=3)
            gradient_mag = np.sqrt(sobelx**2 + sobely**2)
            tenengrad = float(np.mean(gradient_mag))
            
            # Method 3: Modified Laplacian (more robust to noise)
            kernel = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]])
            modified_lap = cv2.filter2D(gray_uint8, -1, kernel)
            modified_lap_score = float(np.abs(modified_lap).mean())
            
            return {
                "laplacian_variance": laplacian_var,
                "tenengrad": tenengrad,
                "modified_laplacian": modified_lap_score
            }
        except Exception as e:
            logger.debug("blur metric failed: %s", e)
            return None

    @staticmethod
    def _noise_estimate(gray: np.ndarray) -> Optional[float]:
        try:
            sig = estimate_sigma(gray, channel_axis=None, average_sigmas=True)
            # estimate_sigma may return a scalar or an array/list per-channel; ensure float
            if isinstance(sig, (list, tuple, np.ndarray)):
                return float(np.mean(sig))
            return float(sig)
        except Exception as e:
            logger.error("noise estimate failed: %s", e)
            return None

    @staticmethod
    def _ocr_extract(img: Image.Image) -> Dict[str, Any]:
        out = {"full_text": None, "blocks": [], "detected_scripts": [], "ocr_engine": None}
        try:
            # Preprocess image for better OCR on dark/low-contrast images
            preprocessed = img.convert('L')  # Convert to grayscale
            
            # Check brightness and enhance if needed
            arr = np.array(preprocessed)
            mean_brightness = np.mean(arr)
            
            if mean_brightness < 100:  # Dark image threshold
                # Increase brightness and contrast
                from PIL import ImageEnhance
                enhancer = ImageEnhance.Brightness(preprocessed)
                preprocessed = enhancer.enhance(1.5)  # Increase brightness by 50%
                enhancer = ImageEnhance.Contrast(preprocessed)
                preprocessed = enhancer.enhance(2.0)  # Double contrast
            
            # Convert back to RGB for Tesseract
            preprocessed = preprocessed.convert('RGB')
            
            txt = pytesseract.image_to_string(preprocessed, config='--psm 3')
            out['full_text'] = txt if txt.strip() else None
            # quick boxes
            data = pytesseract.image_to_data(preprocessed, output_type=pytesseract.Output.DICT)
            n = len(data['text'])
            blocks = []
            for i in range(n):
                t = data['text'][i].strip()
                if not t:
                    continue
                x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                # Handle both int and string types for confidence
                conf_val = data['conf'][i]
                if isinstance(conf_val, (int, float)):
                    conf = float(conf_val) if conf_val != -1 else 0.0
                elif isinstance(conf_val, str):
                    conf = float(conf_val) if (conf_val.isdigit() or conf_val.replace('.', '', 1).replace('-', '', 1).isdigit()) else 0.0
                else:
                    conf = 0.0
                blocks.append({"text": t, "bbox": [x, y, w, h], "confidence": conf, "language": None})
            out['blocks'] = blocks
            # Convert Version object to string for JSON serialization
            version = None
            if hasattr(pytesseract, 'get_tesseract_version'):
                try:
                    ver_obj = pytesseract.get_tesseract_version()
                    version = str(ver_obj) if ver_obj is not None else None
                except Exception:
                    version = None
            out['ocr_engine'] = {"name": "pytesseract", "version": version}
            return out
        except Exception as e:
            logger.error("ocr failed: %s", e)
            return out

    @staticmethod
    def _faces_detect(img: Image.Image) -> Dict[str, Any]:
        """Detect faces using OpenCV's DNN module with pre-trained models."""
        res = {"face_count": None, "faces": [], "face_detection_model": None}
        try:
            # Convert PIL Image to OpenCV format
            arr = np.array(img.convert('RGB'))
            arr_bgr = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)
            h, w = arr_bgr.shape[:2]
            
            # Use OpenCV's Haar Cascade for face detection (built-in, no download needed)
            haar_filename = 'haarcascade_frontalface_default.xml'
            haar_path = None
            try:
                # prefer cv2.data.haarcascades when available (some builds expose cv2.data)
                haarcascades_dir = None
                cv2_data = getattr(cv2, 'data', None)
                if cv2_data is not None:
                    haarcascades_dir = getattr(cv2_data, 'haarcascades', None)
                if not haarcascades_dir:
                    # fallback: derive from cv2 module path
                    haarcascades_dir = os.path.join(os.path.dirname(cv2.__file__), 'data')
                haar_path = os.path.join(haarcascades_dir, haar_filename) if haarcascades_dir else haar_filename
            except Exception:
                haar_path = haar_filename
            face_cascade = cv2.CascadeClassifier(haar_path)
            
            # Detect faces with improved parameters
            gray = cv2.cvtColor(arr_bgr, cv2.COLOR_BGR2GRAY)
            # Enhance contrast for better detection in low-light images
            gray = cv2.equalizeHist(gray)
            
            detected_faces = face_cascade.detectMultiScale(
                gray,
                scaleFactor=1.05,  # Smaller steps for better detection
                minNeighbors=3,     # Lower threshold for more sensitive detection
                minSize=(20, 20),   # Smaller minimum for distant/small faces
                flags=cv2.CASCADE_SCALE_IMAGE
            )
            
            faces = []
            for (x, y, w_box, h_box) in detected_faces:
                # Create a simple embedding hash based on face region pixels
                face_region = arr[y:y+h_box, x:x+w_box]
                embedding_hash = hashlib.sha256(face_region.tobytes()).hexdigest()
                
                faces.append({
                    "face_id": str(uuid.uuid4()),
                    "bbox": [int(x), int(y), int(w_box), int(h_box)],
                    "confidence": None,  # Haar Cascade doesn't provide confidence scores
                    "landmarks": {},
                    "pose": {},
                    "age_estimate": {"value": None, "confidence": None},
                    "gender_estimate": {"value": None, "confidence": None},
                    "is_masked": None,
                    "embedding_hash": embedding_hash,
                    "embedding_kms_ref": None
                })
            
            res['face_count'] = len(faces)
            res['faces'] = faces
            res['face_detection_model'] = {"name": "opencv/haarcascade", "version": cv2.__version__ if hasattr(cv2, '__version__') else None}
            return res
        except Exception as e:
            logger.debug("face detect failed: %s", e)
            return res

    @staticmethod
    def _objects_and_scene(img: Image.Image) -> Dict[str, Any]:
        res = {"object_count": None, "detected_objects": [], "scene_tags": []}
        try:
            model_path = os.path.join(os.path.dirname(__file__), "..", "helpers", "yolov8n.pt")
            model_path = os.path.abspath(model_path)
            model = YOLO(model_path)
            results = model(img)
            objs = []
            for r in results:
                for box in r.boxes:
                    x1, y1, x2, y2 = box.xyxy[0].tolist()
                    conf = float(box.conf[0])
                    cls = int(box.cls[0])
                    label = model.names.get(cls, str(cls))
                    objs.append({"label": label, "score": conf, "bbox": [int(x1), int(y1), int(x2-x1), int(y2-y1)]})
            res['object_count'] = len(objs)
            res['detected_objects'] = objs
            # simple scene tags from object labels
            tags = {}
            for o in objs:
                tags[o['label']] = max(tags.get(o['label'], 0.0), o['score'])
            res['scene_tags'] = [{"tag": k, "score": v} for k, v in tags.items()]
            return res
        except Exception as e:
            logger.debug("object detection failed: %s", e)
            return res

    @staticmethod
    def _nsfw_check(img_bytes: bytes, img: Image.Image) -> Dict[str, Any]:
        out = {"contains_nudity": {"score": None, "label": None}, "nsfw": None, "csem": None}
        try:
            # NudeNet v3.x Detector - works with PIL images and numpy arrays
            # Save temp image for NudeDetector (it needs a file path)
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                img.save(tmp.name)
                tmp_path = tmp.name

            try:
                detector = NudeDetector()
                results = detector.detect(tmp_path)
                
                # Calculate overall NSFW score based on detected parts
                nsfw_labels = ['FEMALE_GENITALIA_EXPOSED', 'MALE_GENITALIA_EXPOSED', 'ANUS_EXPOSED', 
                               'FEMALE_BREAST_EXPOSED', 'BUTTOCKS_EXPOSED']
                max_nsfw_score = 0.0
                
                for detection in results:
                    label = detection.get('class', '')
                    score = detection.get('score', 0.0)
                    if label in nsfw_labels:
                        max_nsfw_score = max(max_nsfw_score, score)
                
                unsafe_score = max_nsfw_score
                label = "unsafe" if unsafe_score > 0.5 else "safe"
                
                out['contains_nudity'] = {"score": float(unsafe_score), "label": label}
                out['nsfw'] = {"score": float(unsafe_score), "label": label, "model": {"name": "NudeNetv3", "version": None}, "heatmap_bbox": None}
            finally:
                # Clean up temp file
                import os
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
            
            # CSEM detection: placeholder - real CSEM detection requires specialist models and lawful access to hash DBs
            out['csem'] = {"score": None, "label": None, "age_estimate": {"value": None, "confidence": None}, "related_indicators": [], "matched_hash_index": {"index_name": None, "match_type": None, "match_score": None}, "model": {"name": None, "version": None}}
            return out
        except Exception as e:
            # Common issue: corrupted ONNX model. User should delete ~/.NudeNet folder
            error_msg = str(e)
            if "INVALID_PROTOBUF" in error_msg or "Protobuf parsing failed" in error_msg or "ONNX" in error_msg:
                import os as os_module
                home_dir = os_module.path.expanduser("~")
                nudenet_path = os_module.path.join(home_dir, ".NudeNet")
                logger.error(
                    "NSFW model corrupted. To fix:\n"
                    f"  1. Delete folder: {nudenet_path}\n"
                    f"  2. Re-run the analysis to download fresh model\n"
                    f"  Error details: {error_msg}"
                )
                out['nsfw'] = {"score": None, "label": "error", "error": "Model corrupted - delete ~/.NudeNet folder", 
                              "model": {"name": "NudeNetv3", "version": None}, "heatmap_bbox": None}
            else:
                logger.debug("nsfw check failed: %s", e)
            return out

    @staticmethod
    def _perceptual_embedding(img: Image.Image) -> Dict[str, Any]:
        out = {"image_embedding_vector": None, "vector_model": {"name": None, "version": None}, "embedding_kms_ref": None}
        try:
            # simple feature extractor using a pretrained ViT (as a proxy for CLIP-like embeddings).
            transform = transforms.Compose([transforms.Resize((224,224)), transforms.ToTensor()])
            model = vit_b_16(weights='DEFAULT')
            model.eval()
            # Apply transforms and ensure we have a torch.Tensor with a batch dimension
            tensor = transform(img.convert('RGB'))
            if not isinstance(tensor, torch.Tensor):
                tensor = torch.tensor(tensor)
            tensor = tensor.unsqueeze(0)
            with torch.no_grad():
                feats = model(tensor)
            vec = feats.squeeze().numpy().tolist()
            out['image_embedding_vector'] = vec[:512] if len(vec) > 512 else vec
            out['vector_model'] = {"name": "vit_b_16", "version": None}
            return out
        except Exception as e:
            logger.debug("embedding failed: %s", e)
            return out

    @staticmethod
    def process(file_data: bytes, file_extension: str, source_path: Optional[str] = None) -> Dict[str, Any]:
        """Process bytes and produce the large JSON structure specified by the user.
        
        file_extension: like '.jpg' or 'png' (used for hints)
        source_path: optional original path for filesystem metadata
        """
        ts = time.time()
        report = {}

        # Basic file info
        file_size = len(file_data) if file_data is not None else None
        img = ImageProcessor._load_image(file_data)
        width = height = img_format = color_mode = channels = None
        dpi = {"x": None, "y": None}
        if img is not None:
            width, height = img.size
            img_format = img.format or (file_extension.replace('.', '').upper() if file_extension else None)
            color_mode = img.mode
            channels = len(img.getbands())
            try:
                info = img.info
                if 'dpi' in info:
                    d = info['dpi']
                    dpi = {"x": _safe_int(d[0]), "y": _safe_int(d[1])}
            except Exception:
                pass

        report['file_info'] = {
            "file_size_bytes": file_size,
            "width": width,
            "height": height,
            "format": img_format,
            "color_mode": color_mode,
            "channels": channels,
            "dpi": dpi
        }

        # filesystem metadata (best-effort: only available if source_path provided)
        fs_meta = {"created_utc": None, "modified_utc": None, "accessed_utc": None, "source_path": None}
        if source_path and os.path.exists(source_path):
            try:
                st = os.stat(source_path)
                fs_meta = {"created_utc": _utc_iso(getattr(st, 'st_ctime', None)),
                           "modified_utc": _utc_iso(getattr(st, 'st_mtime', None)),
                           "accessed_utc": _utc_iso(getattr(st, 'st_atime', None)),
                           "source_path": source_path}
            except Exception:
                pass
        report['filesystem_metadata'] = fs_meta

        # EXIF metadata
        exif_meta = {"camera_make": None, "camera_model": None, "lens_model": None,
                     "capture_datetime_utc": None, "orientation": None, "gps": {"lat": None, "lon": None, "alt": None, "precision_m": None},
                     "exif_raw": {}}
        try:
            if img is not None and hasattr(img, '_getexif'):
                raw = img._getexif() or {}  # type: ignore
                # map tag ids to names
                tagmap = {}
                for k, v in raw.items():
                    name = ExifTags.TAGS.get(k, k)
                    tagmap[name] = v
                exif_meta['exif_raw'] = tagmap
                exif_meta['camera_make'] = tagmap.get('Make')
                exif_meta['camera_model'] = tagmap.get('Model')
                exif_meta['orientation'] = _safe_int(tagmap.get('Orientation'))
                dt = tagmap.get('DateTimeOriginal') or tagmap.get('DateTime')
                if dt:
                    try:
                        # many EXIF datetimes are without timezone; treat as UTC for the report but flag possible inconsistency
                        exif_meta['capture_datetime_utc'] = datetime.strptime(dt, '%Y:%m:%d %H:%M:%S').replace(tzinfo=timezone.utc).isoformat()
                    except Exception:
                        exif_meta['capture_datetime_utc'] = None
                # GPS
                gps = {}
                g = tagmap.get('GPSInfo')
                if g:
                    # best-effort decode
                    try:
                        # many libraries provide already-decoded GPS; handle both forms
                        if isinstance(g, dict):
                            gps = g
                        else:
                            gps = {str(k): v for k, v in g.items()}
                    except Exception:
                        gps = {}
                    # leave lat/lon parsing to external more complete libs
                if gps:
                    # naive conversion if values present in rational format
                    def _conv(coord, ref):
                        try:
                            d, m, s = coord
                            deg = d[0]/d[1] + m[0]/m[1]/60.0 + s[0]/s[1]/3600.0
                            if ref in ['S', 'W']:
                                deg = -deg
                            return deg
                        except Exception:
                            return None
                    # Handle both integer and string keys for GPS data
                    lat_coord = None
                    lat_ref = None
                    lon_coord = None
                    lon_ref = None
                    
                    if isinstance(gps, dict):
                        # Try integer keys first (common in raw EXIF)
                        if 2 in gps:
                            lat_coord = gps[2]  # type: ignore
                        elif 'GPSLatitude' in gps:
                            lat_coord = gps['GPSLatitude']
                        
                        if 1 in gps:
                            lat_ref = gps[1]  # type: ignore
                        elif 'GPSLatitudeRef' in gps:
                            lat_ref = gps['GPSLatitudeRef']
                        
                        if 4 in gps:
                            lon_coord = gps[4]  # type: ignore
                        elif 'GPSLongitude' in gps:
                            lon_coord = gps['GPSLongitude']
                        
                        if 3 in gps:
                            lon_ref = gps[3]  # type: ignore
                        elif 'GPSLongitudeRef' in gps:
                            lon_ref = gps['GPSLongitudeRef']
                    
                    lat = _conv(lat_coord, lat_ref) if lat_coord and lat_ref else None
                    lon = _conv(lon_coord, lon_ref) if lon_coord and lon_ref else None
                    exif_meta['gps']['lat'] = lat
                    exif_meta['gps']['lon'] = lon
        except Exception as e:
            logger.debug("exif parsing failed: %s", e)

        report['exif_metadata'] = exif_meta

        # Visual features
        vf: Dict[str, Any] = {"dominant_colors": None, "color_histogram_summary": None, "entropy": None, "brightness_mean": None, "contrast": None, "edge_density": None, "noise_estimate": None, "blur_metric": None, "jpeg_quant_tables": None, "compression_quality_estimate": None}
        try:
            if img is not None:
                vf['dominant_colors'] = ImageProcessor._dominant_colors(img, n_colors=6)
                arr = np.array(img.convert('RGB'))
                gray = np.array(img.convert('L'))/255.0
                vf['entropy'] = ImageProcessor._entropy(gray)
                vf['brightness_mean'] = float(np.mean(gray))
                vf['contrast'] = float(np.std(gray))
                vf['edge_density'] = ImageProcessor._edge_density_gray(gray)
                vf['noise_estimate'] = ImageProcessor._noise_estimate(gray)
                blur_results = ImageProcessor._blur_metric(gray)
                # Store all blur metrics for better validation
                vf['blur_metric'] = blur_results
                vf['jpeg_quant_tables'] = ImageProcessor._jpeg_quant_signature(file_data)
                # compression quality heuristic for JPEGs
                if img.format and img.format.lower() == 'jpeg':
                    vf['compression_quality_estimate'] = None  # placeholder: estimating JPEG quality is non-trivial
        except Exception as e:
            logger.debug("visual features failed: %s", e)

        report['visual_features'] = vf

        # layout and saliency
        layout: Dict[str, Any] = {"aspect_ratio": None, "orientation_normalized": None, "salient_regions": None, "thumbnail_present": None}
        if width and height:
            try:
                layout['aspect_ratio'] = round(width/height, 4) if height != 0 else None
                if width == height:
                    layout['orientation_normalized'] = 'square'
                elif height > width:
                    layout['orientation_normalized'] = 'portrait'
                else:
                    layout['orientation_normalized'] = 'landscape'
                # simple saliency: crop center box and run edge density
                cx, cy = width//2, height//2
                wbox, hbox = max(1, width//4), max(1, height//4)
                left, top = max(0, cx-wbox//2), max(0, cy-hbox//2)
                thumb = img.crop((left, top, left+wbox, top+hbox)).convert('L') if img is not None else None
                if thumb is not None:
                    sarr = np.array(thumb)/255.0
                    score = ImageProcessor._edge_density_gray(sarr)
                    layout['salient_regions'] = [{"bbox": [left, top, wbox, hbox], "score": score}]
                    layout['thumbnail_present'] = True
            except Exception:
                pass
        report['layout_and_saliency'] = layout

        # objects and scene
        report['objects_and_scene'] = ImageProcessor._objects_and_scene(img) if img is not None else {"object_count": None, "detected_objects": [], "scene_tags": []}

        # faces
        faces = ImageProcessor._faces_detect(img) if img is not None else {"face_count": None, "faces": [], "face_detection_model": None}
        report['faces'] = faces

        # OCR
        report['ocr_and_text'] = ImageProcessor._ocr_extract(img) if img is not None else {"full_text": None, "blocks": [], "detected_scripts": [], "ocr_engine": None}

        # NLP and indicators (lightweight entity extraction)
        nlp = {"detected_languages": [], "extracted_entities": {"emails": [], "phones": [], "urls": [], "ids": []}, "grooming_phrases": {"score": None, "matched_snippets": []}, "translation_to_en": None}
        # basic email/url/phone regex scanning of OCR text
        try:
            txt = report['ocr_and_text'].get('full_text') or ''
            import re
            emails = re.findall(r"[\w\.-]+@[\w\.-]+", txt)
            urls = re.findall(r"https?://[\w\./\-_%]+", txt)
            phones = re.findall(r"\+?\d[\d\-\s]{6,}\d", txt)
            nlp['extracted_entities']['emails'] = list(set(emails))
            nlp['extracted_entities']['phones'] = list(set(phones))
            nlp['extracted_entities']['urls'] = list(set(urls))
        except Exception:
            pass
        report['nlp_and_indicators'] = nlp

        # forensic indicators (best-effort heuristics)
        forensics = {"metadata_manipulation_score": None, "timestamp_inconsistency": {"exif_vs_fs_score": None, "detail": None}, "resampling_detected": {"value": None, "score": None}, "copy_move_detected": {"value": None, "score": None}, "splicing_detected": {"value": None, "score": None}, "double_compression_detected": {"value": None, "score": None}, "image_tamper_summary": []}
        
        # Perform Error Level Analysis (ELA) for JPEG tampering detection
        try:
            if img is not None and img_format and img_format.lower() in ['jpeg', 'jpg']:
                # Save image at quality 90 and compare
                temp_buffer = io.BytesIO()
                img.save(temp_buffer, format='JPEG', quality=90)
                temp_buffer.seek(0)
                resaved = Image.open(temp_buffer)
                
                # Calculate difference (Error Level)
                orig_arr = np.array(img.convert('RGB')).astype(float)
                resaved_arr = np.array(resaved.convert('RGB')).astype(float)
                ela = np.abs(orig_arr - resaved_arr)
                
                # Analyze ELA statistics
                ela_mean = float(np.mean(ela))
                ela_std = float(np.std(ela))
                ela_max = float(np.max(ela))
                
                # High variance in ELA suggests potential tampering
                tamper_score = min(1.0, ela_std / 30.0)  # Normalize to 0-1
                
                forensics['splicing_detected'] = {
                    "value": tamper_score > 0.3,
                    "score": tamper_score,
                    "ela_stats": {"mean": ela_mean, "std": ela_std, "max": ela_max}
                }
                
                if tamper_score > 0.3:
                    forensics['image_tamper_summary'].append(
                        f"Potential splicing detected (ELA score: {tamper_score:.3f})"
                    )
        except Exception as e:
            logger.debug("ELA forensic analysis failed: %s", e)
        
        # Check timestamp inconsistencies
        try:
            exif_dt = exif_meta.get('capture_datetime_utc')
            fs_modified = fs_meta.get('modified_utc')
            
            if exif_dt and fs_modified:
                from dateutil import parser
                exif_time = parser.parse(exif_dt)
                fs_time = parser.parse(fs_modified)
                time_diff = abs((exif_time - fs_time).total_seconds())
                
                # Suspicious if file modified is before EXIF capture time
                if fs_time < exif_time:
                    forensics['timestamp_inconsistency'] = {
                        "exif_vs_fs_score": 1.0,
                        "detail": f"File modified ({fs_modified}) before EXIF capture ({exif_dt})"
                    }
                    forensics['image_tamper_summary'].append("Timestamp inconsistency detected")
                elif time_diff > 86400:  # More than 1 day difference
                    forensics['timestamp_inconsistency'] = {
                        "exif_vs_fs_score": 0.5,
                        "detail": f"Large time gap: {time_diff/86400:.1f} days"
                    }
        except Exception as e:
            logger.debug("Timestamp analysis failed: %s", e)
        
        report['forensic_indicators'] = forensics

        # steganalysis (enhanced with multiple methods)
        stego = {"lsb_anomaly_score": None, "known_stego_signature": {"tool": None, "confidence": None}, "steg_flags": []}
        try:
            if img is not None:
                arr = np.array(img.convert('RGB'))
                
                # Method 1: LSB distribution analysis
                lsb = arr & 1
                scores = [float(lsb[:,:,i].mean()) for i in range(arr.shape[2])]
                lsb_deviation = float(np.mean([abs(s-0.5) for s in scores]))
                stego['lsb_anomaly_score'] = lsb_deviation
                
                # Method 2: Chi-square test for LSB randomness
                chi_square_scores = []
                for channel in range(arr.shape[2]):
                    lsb_channel = lsb[:,:,channel].flatten()
                    observed_0 = np.sum(lsb_channel == 0)
                    observed_1 = np.sum(lsb_channel == 1)
                    expected = len(lsb_channel) / 2
                    
                    # Chi-square statistic
                    chi_sq = ((observed_0 - expected)**2 + (observed_1 - expected)**2) / expected
                    chi_square_scores.append(float(chi_sq))
                
                chi_sq_avg = float(np.mean(chi_square_scores))
                
                # Method 3: Histogram analysis for unusual patterns
                hist_anomalies = []
                for channel in range(arr.shape[2]):
                    hist, _ = np.histogram(arr[:,:,channel].flatten(), bins=256, range=(0, 256))
                    # Check for suspicious patterns (pairs should be similar if LSB stego)
                    pair_diffs = [abs(hist[i] - hist[i+1]) for i in range(0, 255, 2)]
                    avg_pair_diff = np.mean(pair_diffs)
                    hist_anomalies.append(float(avg_pair_diff))
                
                hist_anomaly_score = float(np.mean(hist_anomalies)) / 1000.0  # Normalize
                
                # Combine metrics for overall stego likelihood
                stego_likelihood = (lsb_deviation * 0.4 + min(chi_sq_avg / 100, 1.0) * 0.3 + 
                                   min(hist_anomaly_score, 1.0) * 0.3)
                
                if stego_likelihood > 0.15:
                    stego['steg_flags'].append(f"High stego likelihood: {stego_likelihood:.3f}")
                if chi_sq_avg > 50:
                    stego['steg_flags'].append(f"Chi-square anomaly detected: {chi_sq_avg:.2f}")
                if lsb_deviation > 0.05:
                    stego['steg_flags'].append(f"LSB distribution anomaly: {lsb_deviation:.3f}")
                    
        except Exception as e:
            logger.debug("Steganalysis failed: %s", e)
        report['steganalysis'] = stego

        # perceptual embeddings
        report['perceptual_embeddings'] = ImageProcessor._perceptual_embedding(img) if img is not None else {"image_embedding_vector": None, "vector_model": {"name": None, "version": None}, "embedding_kms_ref": None}

        # network and external (no network lookups here; placeholder)
        report['network_and_external'] = {"detected_urls": [], "detected_domains": [], "image_host": None}

        # derived flags and risks (NSFW, CSEM placeholders)
        nsfw = ImageProcessor._nsfw_check(file_data, img) if img is not None else {"contains_nudity": {"score": None, "label": None}, "nsfw": None, "csem": None}
        derived = {"contains_sensitive_info": None, "contains_nudity": nsfw.get('contains_nudity'), "nsfw": nsfw.get('nsfw'), "csem": nsfw.get('csem'), "synthetic_image_prob": None, "contains_weapon": {"score": None, "label": None}, "low_resolution_flag": (width is not None and height is not None and (width < 320 or height < 320))}
        report['derived_flags_and_risks'] = derived

        # legal and triage
        report['legal_and_triage'] = {"jurisdiction_suspected": [], "mandatory_report_recommended": {"value": False, "reason": None}, "severity_score": None, "escalation": {"level": None, "notify_roles": [], "escalation_timestamp_utc": None}, "evidence_package_ref": {"package_id": None, "signed": None}}

        # pii and victim indicators
        report['pii_and_victim_indicators'] = {"pii_found": {"emails": report['nlp_and_indicators']['extracted_entities']['emails'], "phones": report['nlp_and_indicators']['extracted_entities']['phones'], "ids": [], "confidence": None}, "possible_victim_flag": {"value": False, "evidence": []}, "vulnerable_person_flag": None}

        # storage and provenance
        report['storage_and_provenance'] = {"processor_version": ImageProcessor.VERSION, "processing_timestamp_utc": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(), "processing_steps": ["load", "hash", "exif", "visual", "ocr", "faces", "nsfw", "forensics"], "chain_of_custody": {"ingest_node": None, "tamper_log_ref": None}, "retention_policy_days": None, "redaction_level": None}

        # feature vector summary
        fv = []
        fv_desc = []
        if report['visual_features'].get('entropy') is not None:
            fv.append(float(report['visual_features']['entropy']))
            fv_desc.append("entropy")
        if report['visual_features'].get('edge_density') is not None:
            fv.append(float(report['visual_features']['edge_density']))
            fv_desc.append("edge_density")
        face_count = faces.get('face_count')
        if face_count is not None:
            fv.append(float(face_count))
            fv_desc.append("face_count")
        nsfw_score = None
        try:
            nsfw_score = report['derived_flags_and_risks']['nsfw']['score'] if report['derived_flags_and_risks']['nsfw'] else None
        except Exception:
            nsfw_score = None
        if nsfw_score is not None:
            fv.append(float(nsfw_score))
            fv_desc.append("nsfw_score")
        report['feature_vector_summary'] = {"numeric_vector": fv, "vector_description": fv_desc}

        # quality and confidence
        report['quality_and_confidence'] = {"overall_confidence": None, "failed_checks": [], "notes": []}

        # final additions
        report['storage_and_provenance']['processing_steps'].append('finalize')

        return report

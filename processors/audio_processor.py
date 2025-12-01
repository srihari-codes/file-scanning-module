"""
AudioProcessor module

Provides a single-class API:

class AudioProcessor:
    @classmethod
    def process(cls, file_data: bytes, file_extension: str) -> Dict[str, Any]:

Returns a structured forensic report (dict) matching the schema provided by the user.

Notes:
- This implementation makes best-effort use of common audio libraries (librosa, soundfile, pydub, webrtcvad).
- Many advanced features (production diarization, ASR, acoustic-event detection, music fingerprinting, steganography) are implemented as optional hooks / fallbacks.
- The code is defensive and will return a valid report even when optional libs/models are missing.

Dependencies (recommended):
    pip install numpy scipy librosa soundfile pydub webrtcvad matplotlib
    # Optional / improved results:
    pip install openai-whisper  # for ASR (or use VOSK / other ASR)
    pip install pyannote.audio  # diarization (heavy)

"""
from __future__ import annotations

import io
import os
import uuid
import json
import math
import hashlib
import tempfile
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# try optional imports
try:
    import numpy as np
    import soundfile as sf
    import librosa
    from pydub import AudioSegment
except Exception as e:
    # We'll continue with fallbacks; keep names available for type checks
    np = None  # type: ignore
    sf = None  # type: ignore
    librosa = None  # type: ignore
    AudioSegment = None  # type: ignore

try:
    import silero_vad
except Exception:
    silero_vad = None  # type: ignore

# Optional ASR/diarization imports are intentionally not required here; detect at runtime


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_hashes(data: bytes) -> Dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
    }


class AudioProcessor:
    """Audio forensic processor. All methods are designed to do one job.

    Use:
        report = AudioProcessor.process(file_bytes, '.wav')
    """

    @classmethod
    def process(cls, file_data: bytes, file_extension: str) -> Dict[str, Any]:
        """
        Returns a forensic report dict with only the required fields and calculation logic.
        """
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(suffix=file_extension)
            with os.fdopen(fd, "wb") as f:
                f.write(file_data)
        except Exception:
            tmp_path = None

        report: Dict[str, Any] = {
            "audio_basic": cls.extract_audio_basic(tmp_path),
            "quality_metrics": cls.compute_quality_metrics(tmp_path),
            "speech": cls.speech_processing(tmp_path),
            "nlp": cls.nlp_from_transcript(cls.speech_processing(tmp_path).get("asr", {})),
            "events": [],
            "music_detection": cls.music_detection(tmp_path),
            "steganography_checks": cls.steganography_checks(file_data),
            "anomalies": [],
            "privacy_indicators": {},
            "forensic_signals": {
                "device_signature": None,
                "notes": "device-signature extraction not implemented; placeholder"
            },
            "confidence": cls.estimate_confidence({"speech": cls.speech_processing(tmp_path)}),
            "artifacts": {},
        }

        try:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass

        return report

    @staticmethod
    def extract_audio_basic(path: Optional[str]) -> Dict[str, Any]:
        """Get duration, sample rate, channels, bitdepth and frames_count."""
        out: Dict[str, Any] = {
            "duration_seconds": None,
            "sample_rate": None,
            "bit_depth": None,
            "channels": None,
            "channel_layout": None,
            "frames_count": None,
        }
        if not path:
            return out

        # Prefer soundfile for accurate header reading
        try:
            if sf is not None:
                info = sf.info(path)
                out["sample_rate"] = int(info.samplerate)
                out["channels"] = int(info.channels)
                # duration and frames
                if info.frames is not None and info.samplerate:
                    out["frames_count"] = int(info.frames)
                    out["duration_seconds"] = float(info.frames) / float(info.samplerate)
                out["channel_layout"] = "mono" if info.channels == 1 else "stereo"
                # bit depth detection is not always provided by soundfile
        except Exception:
            logger.debug("soundfile failed to read header, falling back to librosa")

        # fallback to librosa for duration and sample rate
        try:
            if librosa is not None:
                y, sr = librosa.load(path, sr=None, mono=False)
                out.setdefault("sample_rate", int(sr))
                if hasattr(y, 'shape'):
                    if y.ndim == 1:
                        out.setdefault("channels", 1)
                        out.setdefault("frames_count", int(y.shape[0]))
                    else:
                        out.setdefault("channels", int(y.shape[0]))
                        out.setdefault("frames_count", int(y.shape[1]))
                if out.get("frames_count") and out.get("sample_rate"):
                    out.setdefault("duration_seconds", float(out["frames_count"]) / float(out["sample_rate"]))
                out.setdefault("channel_layout", "mono" if out.get("channels") == 1 else "stereo")
        except Exception:
            logger.debug("librosa failed")

        return out

    @staticmethod
    def compute_quality_metrics(path: Optional[str]) -> Dict[str, Any]:
        """Compute RMS, peak, clipping percent, estimated SNR, bitrate (when available)."""
        out: Dict[str, Any] = {
            "rms_db": None,
            "loudness_lufs": None,
            "peak_dbfs": None,
            "clipping_percent": None,
            "snr_db": None,
            "dynamic_range_db": None,
            "bitrate_kbps": None,
            "compression_level_estimate": None,
            "perceptual_quality": None,
        }
        if not path or np is None:
            return out

        try:
            if librosa is not None:
                y, sr = librosa.load(path, sr=None, mono=True)
                # RMS (in dBFS)
                eps = 1e-12
                rms = math.sqrt(float(np.mean(y ** 2)) + eps)
                out["rms_db"] = 20 * math.log10(rms + eps)
                # peak
                peak = float(np.max(np.abs(y)))
                out["peak_dbfs"] = 20 * math.log10(peak + eps)
                # clipping percent
                clipping = float(np.sum(np.abs(y) >= 0.999)) / float(y.size) if y.size > 0 else 0.0
                out["clipping_percent"] = round(clipping * 100.0, 4)
                # simple SNR estimate: treat quietest 5% frames as noise floor
                abs_y = np.abs(y)
                noise_floor = np.percentile(abs_y, 5)
                signal_floor = np.percentile(abs_y, 95)
                if noise_floor > 0:
                    snr = 20 * math.log10((signal_floor + eps) / (noise_floor + eps))
                    out["snr_db"] = round(float(snr), 2)
                # dynamic range approx
                if rms > 0:
                    out["dynamic_range_db"] = round(float(out["peak_dbfs"] - out["rms_db"]), 2) if out["rms_db"] is not None else None
        except Exception:
            logger.exception("quality metrics extraction failed")

        return out

    @staticmethod
    def extract_acoustic_features(path: Optional[str]) -> Dict[str, Any]:
        """MFCCs, chroma, spectral centroid, bandwidth, rolloff, flatness, zcr, mel-spectrogram path."""
        out: Dict[str, Any] = {
            "mfcc": None,
            "chroma": None,
            "spectral_centroid": None,
            "spectral_bandwidth": None,
            "spectral_rolloff": None,
            "spectral_flatness": None,
            "zero_crossing_rate": None,
            "spectral_entropy": None,
            "mel_spectrogram_path": None,
        }
        if not path or librosa is None or np is None:
            return out

        try:
            y, sr = librosa.load(path, sr=None, mono=True)
            # MFCCs aggregated
            mfcc = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
            out["mfcc"] = {"mean": np.mean(mfcc, axis=1).tolist(), "std": np.std(mfcc, axis=1).tolist()}
            # chroma
            chroma = librosa.feature.chroma_stft(y=y, sr=sr)
            out["chroma"] = {"mean": np.mean(chroma, axis=1).tolist()}
            # spectral stats
            centroid = librosa.feature.spectral_centroid(y=y, sr=sr)
            out["spectral_centroid"] = {"mean": float(np.mean(centroid))}
            out["spectral_bandwidth"] = {"mean": float(np.mean(librosa.feature.spectral_bandwidth(y=y, sr=sr)))}
            out["spectral_rolloff"] = {"mean": float(np.mean(librosa.feature.spectral_rolloff(y=y, sr=sr)))}
            out["spectral_flatness"] = {"mean": float(np.mean(librosa.feature.spectral_flatness(y=y)))}
            out["zero_crossing_rate"] = {"mean": float(np.mean(librosa.feature.zero_crossing_rate(y)))}
            # mel spectrogram (save to temp png for artifact reproducibility)
            S = librosa.feature.melspectrogram(y=y, sr=sr)
            logS = librosa.power_to_db(S, ref=np.max)
            # try to save an artifact image
            try:
                import matplotlib.pyplot as plt
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
                plt.figure(figsize=(6, 3))
                librosa.display.specshow(logS, sr=sr, x_axis='time', y_axis='mel')
                plt.title('Mel spectrogram (dB)')
                plt.tight_layout()
                plt.savefig(tmp.name)
                plt.close()
                out["mel_spectrogram_path"] = tmp.name
            except Exception:
                logger.debug("failed to save mel spectrogram image")

        except Exception:
            logger.exception("acoustic feature extraction failed")

        return out

    @staticmethod
    def extract_temporal_features(path: Optional[str]) -> Dict[str, Any]:
        """Silence segments, speech segments (coarse via energy split), tempo, beat positions, onsets."""
        out: Dict[str, Any] = {
            "silence_segments": [],
            "speech_segments": [],
            "tempo_bpm": None,
            "beat_positions": [],
            "onset_times": [],
        }
        if not path or librosa is None or np is None:
            return out

        try:
            y, sr = librosa.load(path, sr=None, mono=True)
            # split on non-silent intervals
            intervals = librosa.effects.split(y, top_db=40)
            sils = []
            speeches = []
            for i in intervals:
                start = float(i[0]) / sr
                end = float(i[1]) / sr
                speeches.append({"start": start, "end": end, "duration": end - start, "energy": float(np.sum(y[i[0]:i[1]] ** 2))})
            out["speech_segments"] = speeches
            # Silence segments as inverse
            last = 0
            for i in intervals:
                s = float(last) / sr
                e = float(i[0]) / sr
                if e - s > 0:
                    sils.append({"start": s, "end": e, "duration": e - s, "energy": float(np.sum(y[int(last):int(i[0])] ** 2))})
                last = int(i[1])
            out["silence_segments"] = sils
            # tempo and beats
            tempo, beats = librosa.beat.beat_track(y=y, sr=sr)
            out["tempo_bpm"] = float(tempo)
            out["beat_positions"] = librosa.frames_to_time(beats, sr=sr).tolist()
            # onset times
            onsets = librosa.onset.onset_detect(y=y, sr=sr, units='time')
            out["onset_times"] = onsets.tolist()
        except Exception:
            logger.exception("temporal features extraction failed")

        return out

    @staticmethod
    def speech_processing(path: Optional[str]) -> Dict[str, Any]:
        """VAD segments, diarization placeholder, ASR placeholder (attempt whisper if installed), language detection.

        The function returns:
            {"vad_confidence":..., "vad_segments": [...], "diarization": [...], "asr": {...}, "language_detection": {...}}
        """
        out: Dict[str, Any] = {
            "vad_confidence": None,
            "diarization": [],
            "asr": {},
            "language_detection": {},
            "speech_rate_wpm": None,
            "pauses_stats": None,
        }
        if not path:
            return out

        # VAD using Silero VAD if available
        try:
            if silero_vad is not None and sf is not None and np is not None:
                # Read audio as mono, 16kHz PCM float32
                wav, sr = sf.read(path)
                if isinstance(wav, np.ndarray) and wav.ndim > 1:
                    wav = wav.mean(axis=1)
                # Resample if needed
                if sr != 16000 and librosa is not None:
                    wav = librosa.resample(wav, orig_sr=sr, target_sr=16000)
                    sr = 16000
                # Convert to float32 numpy array
                if wav.dtype != np.float32:
                    wav = wav.astype(np.float32)
                # Convert numpy array to torch tensor
                import torch
                wav_tensor = torch.from_numpy(wav)
                # Get speech timestamps
                speech_timestamps = silero_vad.get_speech_timestamps(wav_tensor, silero_vad.load_silero_vad(), sampling_rate=sr)
                out["vad_confidence"] = 0.8 if len(speech_timestamps) > 0 else 0.2
        except Exception:
            logger.debug("Silero VAD failed")

        # ASR: try whisper if installed (best-effort). If not available, leave placeholder.
        try:
            import whisper
            model = whisper.load_model("small")
            res = model.transcribe(path)
            # Filter segments to only keep start, end, text, language
            filtered_segments = []
            for seg in res.get("segments", []):
                if isinstance(seg, dict):
                    filtered_segments.append({
                        "start": seg.get("start"),
                        "end": seg.get("end"),
                        "text": seg.get("text")
                    })
            out["asr"] = {
                "transcript": res.get("text"),
                "segments": filtered_segments,
                "language": res.get("language")
            }
            out["speech_rate_wpm"] = None
            out["language_detection"] = {"language": res.get("language"), "confidence": None}
        except Exception:
            # whisper not installed or failed: leave as empty dict
            out.setdefault("asr", {})

        # simple diarization placeholder (not production grade)
        try:
            # crude speaker turn detection: cluster by RMS energy changes (placeholder)
            out.setdefault("diarization", [])
        except Exception:
            logger.debug("diarization fallback failed")

        return out

    @staticmethod
    def nlp_from_transcript(asr_block: Dict[str, Any]) -> Dict[str, Any]:
        """Run lightweight NLP on ASR transcript: entities, keywords, sentiment, profanity flags.
        This is a placeholder that calls no external cloud services.
        """
        out: Dict[str, Any] = {
            "entities": [],
            "keywords": [],
            "sentiment": {"score": None, "label": None},
            "intent_tags": [],
            "profanity_flags": [],
        }
        text = None
        if isinstance(asr_block, dict):
            text = asr_block.get("transcript")
        if not text:
            return out

        # naive detections
        # phone numbers
        import re
        phones = re.findall(r"\+?\d[\d\-\s]{6,}\d", text)
        out["entities"] = [{"type": "PHONE", "value": p} for p in phones]
        # keywords: top words excluding stopwords
        try:
            from collections import Counter
            words = re.findall(r"\w+", text.lower())
            stop = set(["the", "and", "a", "to", "is", "it", "of", "in", "that", "i"])
            filtered = [w for w in words if w not in stop and len(w) > 2]
            c = Counter(filtered)
            out["keywords"] = [{"word": w, "count": n} for w, n in c.most_common(15)]
        except Exception:
            pass
        # profanity (naive)
        bad = ["fuck", "shit", "bitch"]
        prof = [w for w in bad if w in text.lower()]
        out["profanity_flags"] = prof
        return out

    @staticmethod
    def music_detection(path: Optional[str]) -> Dict[str, Any]:
        out: Dict[str, Any] = {"is_music": None, "music_confidence": None, "music_fingerprint": None, "matched_track": None}
        if not path or librosa is None or np is None:
            return out
        try:
            y, sr = librosa.load(path, sr=None, mono=True)
            # heuristic: if harmonic energy >> percussive and tonal features present then music
            S = np.abs(librosa.stft(y))
            spectral_centroid = np.mean(librosa.feature.spectral_centroid(S=S, sr=sr))
            flatness = np.mean(librosa.feature.spectral_flatness(S=S))
            # simple thresholding heuristic
            is_music = flatness < 0.2 and spectral_centroid < 3000
            out["is_music"] = bool(is_music)
            out["music_confidence"] = 0.7 if is_music else 0.3
        except Exception:
            logger.debug("music detection heuristic failed")
        return out

    @staticmethod
    def steganography_checks(file_data: bytes) -> Dict[str, Any]:
        """Very basic LSB entropy check on raw bytes — not a replacement for proper steg tools."""
        out: Dict[str, Any] = {"lsb_entropy": None, "steg_anomaly_score": None, "matched_steg_patterns": [], "notes": None}
        try:
            b = bytearray(file_data)
            if len(b) < 100:
                return out
            # compute LSB distribution
            ones = 0
            zeros = 0
            for x in b[:2000]:
                if x & 1:
                    ones += 1
                else:
                    zeros += 1
            total = ones + zeros
            if total > 0:
                p = ones / total
                # entropy of bernoulli
                eps = 1e-12
                ent = -(p * math.log2(p + eps) + (1 - p) * math.log2(1 - p + eps))
                out["lsb_entropy"] = round(ent, 4)
                out["steg_anomaly_score"] = round(abs(0.5 - p) * 2, 4)  # 0 => random, 1 => fully biased
                out["notes"] = "LSB heuristic only; for deep analysis run dedicated steg tools"
        except Exception:
            logger.exception("steg check failed")

        return out

    @staticmethod
    def detect_anomalies(path: Optional[str], report: Dict[str, Any]) -> List[Dict[str, Any]]:
        anomalies: List[Dict[str, Any]] = []
        # placeholder anomalies based on mismatches
        if not path:
            return anomalies
        # Example: if sample_rate missing
        if not report.get("audio_basic", {}).get("sample_rate"):
            anomalies.append({"type": "sample_rate_missing", "confidence": 0.5, "notes": "header missing or unreadable"})
        return anomalies

    @staticmethod
    def estimate_confidence(report: Dict[str, Any]) -> Dict[str, Optional[float]]:
        c: Dict[str, Optional[float]] = {
            "transcript_confidence": None,
            "diarization_confidence": None,
            "event_detection_confidence": None,
            "stego_confidence": None,
        }
        # simple heuristic: if ASR contains text, boost transcript_confidence
        if report.get("speech", {}).get("asr", {}).get("transcript"):
            c["transcript_confidence"] = 0.8
        else:
            c["transcript_confidence"] = 0.2
        return c

    @staticmethod
    def make_summary(report: Dict[str, Any]) -> Dict[str, Any]:
        short_text = "Auto-generated audio forensic report."
        key_findings: List[str] = []
        # Phone numbers
        phones = report.get("nlp", {}).get("entities", [])
        if phones:
            key_findings.append(f"Phone numbers present: {[e['value'] for e in phones]}")
        if report.get("music_detection", {}).get("is_music"):
            key_findings.append("Contains music segments (music detection positive)")
        if report.get("quality_metrics", {}).get("clipping_percent") and report["quality_metrics"]["clipping_percent"] > 0:
            key_findings.append("Clipping detected")
        priority = "low"
        if any(["Phone numbers present" in k for k in key_findings]):
            priority = "high"
        return {"short_text": short_text, "key_findings": key_findings, "priority_hint": priority}


if __name__ == "__main__":
    # simple CLI demo: read a file path and print a JSON report
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("file", help="audio file to analyze")
    args = p.parse_args()
    with open(args.file, "rb") as fh:
        data = fh.read()
    rep = AudioProcessor.process(data, os.path.splitext(args.file)[1])
    print(json.dumps(rep, indent=2))

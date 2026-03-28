from __future__ import annotations

import sys
sys.set_int_max_str_digits(0)  # Disable limit for large integer-to-string conversions

import base64
import gzip
import io
import json
import lzma
import os
import tempfile
import zlib
import ctypes

# Configure OpenJPEG path before importing glymur
_openjpeg_bin = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin")
if os.path.exists(_openjpeg_bin):
    os.environ["PATH"] = _openjpeg_bin + os.pathsep + os.environ.get("PATH", "")
    # Pre-load the DLL so glymur can find it
    _opj_dll = os.path.join(_openjpeg_bin, "openjp2.dll")
    if os.path.exists(_opj_dll):
        try:
            ctypes.CDLL(_opj_dll)
            print(f"Loaded OpenJPEG DLL: {_opj_dll}")
        except Exception as e:
            print(f"Failed to load OpenJPEG DLL: {e}")

import cv2
import numpy as np
import qrcode
from flask import Flask, jsonify, render_template, request, send_file
from PIL import Image, ImageOps, ImageDraw

# Test glymur after OpenJPEG is loaded
try:
    import glymur
    print(f"glymur version: {glymur.__version__}")
    print(f"glymur openjp2 path: {glymur.lib.openjp2.OPENJP2}")
except ImportError:
    print("glymur not installed")
except Exception as e:
    print(f"glymur info error: {e}")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


# ----------------------------
# Temp cache helper
# ----------------------------
def save_debug(name, data):
    try:
        path = os.path.join(tempfile.gettempdir(), name)
        with open(path, "wb") as f:
            f.write(data)
        return path
    except:
        return None


# ----------------------------
# Errors
# ----------------------------
class QRAppError(Exception):
    def __init__(self, code, message, detail=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail


def make_error(code, message, detail=None, status=400):
    payload = {"ok": False, "error": {"code": code, "message": message}}
    if detail:
        payload["error"]["detail"] = detail
    return jsonify(payload), status


# ----------------------------
# Image helpers
# ----------------------------
def image_bytes_to_pil(image_bytes):
    try:
        img = Image.open(io.BytesIO(image_bytes))
        return ImageOps.exif_transpose(img).convert("RGB")
    except Exception as e:
        raise QRAppError("INVALID_IMAGE", "Invalid image", str(e))


def pil_to_cv(img):
    return cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)


# ----------------------------
# QR Detection (VERY STRONG)
# ----------------------------
def try_decode_qr(img):
    detector = cv2.QRCodeDetector()

    variants = []

    # original
    variants.append(img)

    # upscale (CRITICAL)
    for scale in [2, 3, 4, 5]:
        w, h = img.size
        variants.append(img.resize((w * scale, h * scale)))

    for v in variants:
        cv_img = pil_to_cv(v)

        # multi decode
        try:
            ok, decoded_info, _, _ = detector.detectAndDecodeMulti(cv_img)
            if ok and decoded_info:
                for d in decoded_info:
                    if d and len(d) > 100:
                        return d
        except (cv2.error, ValueError, TypeError):
            pass

        # single decode
        try:
            data, _, _ = detector.detectAndDecode(cv_img)
            if data and len(data) > 100:
                return data
        except (cv2.error, ValueError, TypeError):
            pass

    # fallback pyzbar
    try:
        from pyzbar.pyzbar import decode
        decoded = decode(pil_to_cv(img))
        if decoded:
            return decoded[0].data.decode("utf-8", errors="ignore")
    except (ImportError, IndexError, AttributeError, UnicodeDecodeError):
        pass

    raise QRAppError("QR_NOT_FOUND", "Failed to decode QR")


# ----------------------------
# Decompression
# ----------------------------
# Maximum decompressed size: 10MB (real Aadhaar QR codes are ~1-2KB)
MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024

def try_decompress(blob):
    import bz2

    methods = [
        ("gzip", lambda b: gzip.decompress(b)),
        ("zlib", lambda b: zlib.decompress(b)),
        ("deflate", lambda b: zlib.decompress(b, -15)),
        ("bz2", lambda b: bz2.decompress(b)),
        ("lzma", lambda b: lzma.decompress(b)),
    ]

    for name, func in methods:
        try:
            decompressed = func(blob)
            # Validate decompressed size to prevent decompression bombs
            if len(decompressed) > MAX_DECOMPRESSED_SIZE:
                continue
            return decompressed, name
        except (zlib.error, lzma.LZMAError, gzip.BadGzipFile, bz2.Error, MemoryError, OSError):
            continue
        except Exception:
            continue

    return None, None


# ----------------------------
# Extract JPEG
# ----------------------------
def extract_image(blob):
    # Try JPEG (FFD8...FFD9)
    if b"\xff\xd8" in blob:
        start = blob.find(b"\xff\xd8")
        end = blob.rfind(b"\xff\xd9")  # Use rfind for last occurrence
        if end > start:
            return blob[start:end + 2], "jpeg"

    # Try PNG (89 50 4E 47)
    png_header = b"\x89PNG"
    if png_header in blob:
        start = blob.find(png_header)
        # PNG ends with IEND chunk (4-byte length + "IEND" + 4-byte CRC = 12 bytes)
        iend = blob.find(b"IEND", start)
        if iend > start:
            # Include the entire IEND chunk (4 bytes before "IEND" + 4 bytes + 4 bytes CRC after)
            return blob[start:iend + 8], "png"

    # Try JPEG2000 codestream (FF4F FF51)
    j2k_marker = b"\xff\x4f\xff\x51"
    if j2k_marker in blob:
        start = blob.find(j2k_marker)
        # J2K ends with EOC marker FF D9
        end = blob.rfind(b"\xff\xd9")
        if end > start:
            return blob[start:end + 2], "jpeg2000"
        else:
            # Return from start to end of data
            return blob[start:], "jpeg2000"

    # Try JPEG2000 JP2 container (starts with 00 00 00 0C 6A 50)
    jp2_marker = b"\x00\x00\x00\x0c\x6a\x50"
    if jp2_marker in blob:
        start = blob.find(jp2_marker)
        return blob[start:], "jp2"

    return None, None


# ----------------------------
# Convert JPEG2000 to JPEG using Pillow
# ----------------------------
def convert_j2k_to_jpeg(j2k_data):
    """Convert JPEG2000 data to regular JPEG"""
    try:
        # Try using Pillow (needs pillow with jpeg2000 support)
        img = Image.open(io.BytesIO(j2k_data))
        buf = io.BytesIO()
        img.convert("RGB").save(buf, format="JPEG", quality=85)
        return buf.getvalue()
    except Exception:
        return None


# ----------------------------
# Face Detection and Cropping
# ----------------------------
def detect_and_crop_face(image_bytes):
    """Detect face in image and crop to face region"""
    try:
        # Load image
        img = Image.open(io.BytesIO(image_bytes))
        img_array = np.array(img.convert('RGB'))

        # Convert to BGR for OpenCV
        img_bgr = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
        gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)

        # Load cascade classifier for face detection
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

        # Detect faces
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))

        if len(faces) > 0:
            # Get the largest face
            largest_face = max(faces, key=lambda f: f[2] * f[3])
            x, y, w, h = largest_face

            # Add some padding around face (20%)
            padding = int(max(w, h) * 0.2)
            x1 = max(0, x - padding)
            y1 = max(0, y - padding)
            x2 = min(img_array.shape[1], x + w + padding)
            y2 = min(img_array.shape[0], y + h + padding)

            # Crop face
            face_img = img_array[y1:y2, x1:x2]

            # Convert back to PIL
            face_pil = Image.fromarray(face_img)

            return face_pil, True

        # No face detected, return original
        return img, False

    except Exception as e:
        # Return original image if face detection fails
        return Image.open(io.BytesIO(image_bytes)), False


# ----------------------------
# Parse structured binary format (like Aadhaar QR)
# Format: may have length-prefixed fields or XML/JSON
# ----------------------------
def parse_binary_payload(data):
    """Try to parse various binary formats used in ID QR codes"""
    result = {"text": None, "image": None, "format": None, "image_type": None}

    # Check for XML
    if data.startswith(b"<?xml") or data.startswith(b"<"):
        try:
            result["text"] = data.decode("utf-8")
            result["format"] = "xml"
            return result
        except:
            pass

    # Check for JSON
    if data.startswith(b"{") or data.startswith(b"["):
        try:
            result["text"] = data.decode("utf-8")
            result["format"] = "json"
            return result
        except:
            pass

    # Try to find image in various positions
    # Look for JPEG/PNG/JPEG2000 anywhere in the data
    jpeg_start = data.find(b"\xff\xd8\xff")
    png_start = data.find(b"\x89PNG")
    j2k_start = data.find(b"\xff\x4f\xff\x51")  # JPEG2000 codestream
    jp2_start = data.find(b"\x00\x00\x00\x0c\x6a\x50")  # JP2 container

    # Find the earliest image marker
    img_positions = []
    if jpeg_start >= 0:
        img_positions.append((jpeg_start, "jpeg"))
    if png_start >= 0:
        img_positions.append((png_start, "png"))
    if j2k_start >= 0:
        img_positions.append((j2k_start, "jpeg2000"))
    if jp2_start >= 0:
        img_positions.append((jp2_start, "jp2"))

    img_start = -1
    img_type = None

    if img_positions:
        img_positions.sort(key=lambda x: x[0])
        img_start, img_type = img_positions[0]

    if img_start > 0:
        # Text is before the image
        text_part = data[:img_start]
        img_part = data[img_start:]
        
        # Also check if there's text AFTER the image (some formats have additional data)
        text_after = None
        if img_type in ("jpeg2000", "jp2"):
            eoc = data.rfind(b"\xff\xd9", img_start)
            if eoc > img_start and eoc + 2 < len(data):
                remaining = data[eoc + 2:]
                if len(remaining) > 10:
                    try:
                        decoded_after = remaining.decode("utf-8", errors="ignore")
                        printable_after = "".join(c for c in decoded_after if c.isprintable() or c in "\n\r\t ")
                        if len(printable_after.strip()) > 5:
                            text_after = printable_after.strip()
                    except Exception:
                        pass

        # CRITICAL: Use latin-1 FIRST because UTF-8 drops \xff bytes!
        # latin-1 maps each byte 0-255 directly to unicode 0-255
        try:
            # Skip leading control bytes but KEEP \xff delimiter
            clean_text = text_part.lstrip(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f")

            # Use latin-1 which preserves ALL bytes including \xff
            decoded = clean_text.decode("latin-1")

            # CRITICAL: Keep \xff delimiter (ord 255)
            # Filter but preserve: printable ASCII + delimiter (255) + special chars
            decoded_with_delim = ""
            for c in decoded:
                code = ord(c)
                # Keep: printable ASCII (32-126), delimiter (255), space, special chars
                if (32 <= code <= 126) or code == 255 or c in "\n\r\t":
                    decoded_with_delim += c

            if len(decoded_with_delim) > 10:
                result["text"] = decoded_with_delim.strip()
                # Append text found after image if any
                if text_after:
                    result["text"] = result["text"] + text_after
        except Exception:
            pass

        # Extract image based on type
        if img_type == "jpeg":
            end = data.rfind(b"\xff\xd9")
            if end > img_start:
                result["image"] = data[img_start:end + 2]
                result["format"] = "binary+jpeg"
                result["image_type"] = "jpeg"
        elif img_type == "png":
            # PNG ends with IEND chunk (4-byte length + "IEND" + 4-byte CRC = 12 bytes)
            iend = data.find(b"IEND", img_start)
            if iend > img_start:
                # Include the entire IEND chunk
                result["image"] = data[img_start:iend + 8]
                result["format"] = "binary+png"
                result["image_type"] = "png"
        elif img_type in ("jpeg2000", "jp2"):
            # JPEG2000 - take from start marker to end
            # J2K ends with EOC (FFD9) but may not have it
            eoc = data.rfind(b"\xff\xd9", img_start)
            if eoc > img_start:
                result["image"] = data[img_start:eoc + 2]
            else:
                result["image"] = data[img_start:]
            result["format"] = f"binary+{img_type}"
            result["image_type"] = img_type

    # If no image found, try to decode entire thing as text
    if result["text"] is None and result["image"] is None:
        # Maybe it's all text with some binary prefix
        for encoding in ["utf-8", "latin-1", "cp1252"]:
            try:
                decoded = data.decode(encoding, errors="ignore")
                printable = "".join(c for c in decoded if c.isprintable() or c in "\n\r\t ")
                if len(printable) > 20:
                    result["text"] = printable.strip()
                    result["format"] = "text_extracted"
                    break
            except:
                continue

    return result


# ----------------------------
# Parse Aadhaar QR text format into structured fields
# ----------------------------
# Indian states and union territories set for efficient lookup
INDIAN_STATES = {
    'West Bengal', 'Bihar', 'Jharkhand', 'Odisha', 'Assam', 'Maharashtra',
    'Gujarat', 'Rajasthan', 'Uttar Pradesh', 'Madhya Pradesh', 'Karnataka',
    'Tamil Nadu', 'Kerala', 'Andhra Pradesh', 'Telangana', 'Punjab', 'Haryana',
    'Delhi', 'Chhattisgarh', 'Uttarakhand', 'Himachal Pradesh', 'Jammu and Kashmir',
    'Goa', 'Tripura', 'Meghalaya', 'Manipur', 'Nagaland', 'Mizoram', 'Sikkim',
    'Arunachal Pradesh', 'Puducherry', 'Chandigarh', 'Dadra and Nagar Haveli',
    'Daman and Diu', 'Lakshadweep', 'Andaman and Nicobar Islands'
}

def parse_aadhaar_text(text):
    """
    Parse Aadhaar Secure QR V2 text format into structured fields.
    
    Format uses \xff (byte 255) as field delimiter:
    V[version]\xff[ref]\xff[aadhaar_timestamp_ref]\xff[Name]\xff[DOB]\xff[Gender]\xff[Guardian]\xff[District]\xff\xff[localities...]\xff[Mobile]\xff[Email]...
    """
    import re
    
    result = {
        "aadhaar": None,
        "timestamp": None,
        "name": None,
        "gender": None,
        "dob": None,
        "mobile": None,
        "email": None,
        "address": None,
        "version": None,
        "parsed": False
    }
    
    if not text or len(text) < 50:
        return result

    # Split by \xff delimiter (appears as ÿ character)
    delimiter = '\xff' if '\xff' in text else 'ÿ'
    fields = text.split(delimiter)
    
    try:
        # Field structure (may vary by version):
        # 0: V5
        # 1: 3 (sub-version?)
        # 2: 687520260327084607509 (aadhaar last 4 + timestamp + ref)
        # 3: Name
        # 4: DOB
        # 5: Gender
        # 6: Guardian (C/O S/O...)
        # 7+: Address components (district, localities, PIN, state, etc.)
        # Last few: Mobile, Email
        
        if len(fields) > 0 and fields[0].startswith('V'):
            result["version"] = fields[0][1] if len(fields[0]) > 1 else None
        
        # Parse aadhaar + timestamp from field 2
        if len(fields) > 2 and len(fields[2]) >= 16:
            data = fields[2]
            # Last 4 digits of Aadhaar at start
            aadhaar_last4 = data[0:4]
            if aadhaar_last4.isdigit():
                result["aadhaar"] = f"XXXX XXXX {aadhaar_last4}"
            
            # Timestamp: YYYYMMDDHHMM (12 digits after aadhaar)
            if len(data) >= 16:
                ts_part = data[4:16]
                if ts_part.isdigit():
                    year, month, day = ts_part[0:4], ts_part[4:6], ts_part[6:8]
                    hour, minute = ts_part[8:10], ts_part[10:12]
                    result["timestamp"] = f"{day}/{month}/{year}  {hour}:{minute} {'am' if int(hour) < 12 else 'pm'}"
        
        # Field 3: Name
        if len(fields) > 3:
            result["name"] = fields[3].strip()
        
        # Field 4: DOB
        if len(fields) > 4:
            result["dob"] = fields[4].strip()
        
        # Field 5: Gender
        if len(fields) > 5:
            result["gender"] = fields[5].strip()
        
        # Fields 6+: Address components
        # Official Aadhaar app shows address as:
        # Guardian, [localities], Post Office, District, State - PIN
        # But fields come as: Guardian, District, '', localities..., PIN, PO, State, localities...
        # We need to reorder: Guardian + localities (in reverse order) + PO + District + State - PIN
        
        addr_fields = []
        pin_code = None
        district = None  # Field 7 is typically district
        state = None
        
        for i in range(6, len(fields)):
            field = fields[i].strip()
            if not field:
                continue
            # Stop if we hit mobile pattern
            if re.match(r'^X{6}\d{4}$', field):
                result["mobile"] = field
                # Email might be next field
                if i + 1 < len(fields):
                    email_field = fields[i + 1].strip()
                    if '@' in email_field:
                        # Improved email regex: username@domain
                        email_match = re.search(r'([a-z0-9][a-z0-9xX._-]*@[a-z0-9][a-z0-9xX._-]*\.[a-z]{2,})', email_field, re.I)
                        result["email"] = email_match.group(1) if email_match else email_field
                break
            # Check for email pattern
            if '@' in field:
                # Improved email regex: username@domain
                email_match = re.search(r'([a-z0-9][a-z0-9xX._-]*@[a-z0-9][a-z0-9xX._-]*\.[a-z]{2,})', field, re.I)
                if email_match:
                    result["email"] = email_match.group(1)
                    break
            # Identify PIN code (6 digits)
            if re.match(r'^\d{6}$', field):
                pin_code = field
                continue
            # Identify State (common Indian states) - use set for O(1) lookup
            if field in INDIAN_STATES:
                state = field
                continue
            addr_fields.append(field)
        
        # Build address: all addr fields + state - PIN
        if addr_fields:
            addr_str = ", ".join(addr_fields)
            if state and pin_code:
                addr_str += f", {state} - {pin_code}."
            elif state:
                addr_str += f", {state}."
            elif pin_code:
                addr_str += f" - {pin_code}."
            else:
                addr_str += "."
            result["address"] = addr_str

        # Mark as parsed
        if result.get("name") or result.get("aadhaar"):
            result["parsed"] = True

    except Exception:
        pass
    
    return result


# ----------------------------
# SEPARATOR for text+image format
# ----------------------------
# SEPARATOR for text+image format
# ----------------------------
SEPARATOR = b"\x00\x00\x00\x00IMGSTART\x00\x00\x00\x00"


# ----------------------------
# MAIN DECODER WITH CACHE 🔥
# ----------------------------
# Maximum numeric string length: 100K characters (real Aadhaar is ~3000)
MAX_NUMERIC_STRING_LENGTH = 100000

def decode_payload(raw):
    steps = []
    debug = {
        "attempts": [],
        "success": None,
    }

    result = {
        "type": "unknown",
        "text": None,
        "image_found": False,
        "debug": debug,
        "steps": steps,
        "raw_preview": raw[:200] + "..." if len(raw) > 200 else raw,
        "decompressed_hex": None,
    }

    # Step 1: Check if numeric
    if not raw.isdigit():
        steps.append({"msg": "Data is plain text (not numeric)", "ok": True})
        result["text"] = raw
        result["type"] = "plain_text"
        return result

    steps.append({"msg": f"QR contains numeric data ({len(raw)} digits)", "ok": True})

    # Validate numeric string length to prevent integer conversion DoS
    if len(raw) > MAX_NUMERIC_STRING_LENGTH:
        steps.append({"msg": f"Numeric string too long ({len(raw)} > {MAX_NUMERIC_STRING_LENGTH})", "ok": False})
        raise QRAppError("NUMERIC_TOO_LONG", f"Numeric data exceeds maximum length of {MAX_NUMERIC_STRING_LENGTH}")

    try:
        n = int(raw)
    except (ValueError, MemoryError) as e:
        steps.append({"msg": f"Failed to convert numeric string to integer: {e}", "ok": False})
        raise QRAppError("INVALID_NUMERIC", "Failed to convert numeric data to integer")

    base_len = (n.bit_length() + 7) // 8
    steps.append({"msg": f"Converted to big integer, base byte length: {base_len}", "ok": True})

    # Try different byte lengths (leading zeros get lost in decimal)
    for extra in range(0, 50):
        try:
            blob = n.to_bytes(base_len + extra, "big")

            debug["attempts"].append({
                "extra": extra,
                "size": len(blob),
                "hex_preview": blob[:20].hex()
            })

            save_debug(f"attempt_{extra}.bin", blob)

            decompressed, method = try_decompress(blob)

            if decompressed:
                save_debug("SUCCESS_DECOMPRESSED.bin", decompressed)

                steps.append({"msg": f"Decompression SUCCESS with {method} (extra={extra}, size={len(blob)} bytes)", "ok": True})
                steps.append({"msg": f"Decompressed size: {len(decompressed)} bytes", "ok": True})

                result["type"] = f"compressed:{method}"
                # Show first 200 bytes hex for debugging
                result["decompressed_hex"] = decompressed[:200].hex()
                # Also show printable chars
                printable_preview = "".join(chr(b) if 32 <= b < 127 else "." for b in decompressed[:100])
                result["decompressed_ascii"] = printable_preview

                # Check for our structured format (text + separator + image)
                if SEPARATOR in decompressed:
                    steps.append({"msg": "Found SEPARATOR marker (structured format)", "ok": True})
                    parts = decompressed.split(SEPARATOR, 1)
                    text_part = parts[0]
                    image_part = parts[1] if len(parts) > 1 else None

                    try:
                        result["text"] = text_part.decode("utf-8")
                        steps.append({"msg": f"Text decoded: {len(result['text'])} chars", "ok": True})
                    except:
                        result["text"] = text_part.decode("latin-1")
                        steps.append({"msg": f"Text decoded (latin-1): {len(result['text'])} chars", "ok": True})

                    if image_part and len(image_part) > 0:
                        result["image_found"] = True
                        result["image_base64"] = base64.b64encode(image_part).decode()
                        save_debug("extracted.jpg", image_part)
                        steps.append({"msg": f"Image extracted: {len(image_part)} bytes", "ok": True})
                    else:
                        steps.append({"msg": "No image after separator", "ok": False})
                else:
                    steps.append({"msg": "No SEPARATOR found, trying binary format parsing", "ok": True})

                    # Use the binary parser
                    parsed = parse_binary_payload(decompressed)

                    if parsed["format"]:
                        steps.append({"msg": f"Detected format: {parsed['format']}", "ok": True})

                    if parsed["text"]:
                        result["text"] = parsed["text"]
                        steps.append({"msg": f"Text extracted: {len(parsed['text'])} chars", "ok": True})
                    else:
                        steps.append({"msg": "No readable text found", "ok": False})

                    if parsed["image"]:
                        img_data = parsed["image"]
                        img_type = parsed.get("image_type", "unknown")

                        # Convert JPEG2000 to regular JPEG for browser display
                        if img_type in ("jpeg2000", "jp2"):
                            steps.append({"msg": f"Found JPEG2000 image, converting...", "ok": True})
                            converted = convert_j2k_to_jpeg(img_data)
                            if converted:
                                img_data = converted
                                steps.append({"msg": f"Converted to JPEG: {len(converted)} bytes", "ok": True})
                            else:
                                steps.append({"msg": "JPEG2000 conversion failed, trying raw", "ok": False})

                        result["image_found"] = True
                        result["image_base64"] = base64.b64encode(img_data).decode()
                        save_debug("extracted_image.bin", img_data)
                        steps.append({"msg": f"Image extracted ({img_type}): {len(parsed['image'])} bytes", "ok": True})
                    else:
                        # Fallback: try old JPEG extraction
                        img, img_type = extract_image(decompressed)
                        if img:
                            # Convert JPEG2000 if needed
                            if img_type in ("jpeg2000", "jp2"):
                                steps.append({"msg": f"Found {img_type} image, converting...", "ok": True})
                                converted = convert_j2k_to_jpeg(img)
                                if converted:
                                    img = converted
                                    steps.append({"msg": f"Converted to JPEG", "ok": True})

                            result["image_found"] = True
                            result["image_base64"] = base64.b64encode(img).decode()
                            save_debug("extracted.jpg", img)
                            steps.append({"msg": f"{img_type.upper()} extracted: {len(img)} bytes", "ok": True})
                        else:
                            steps.append({"msg": "No image found (tried JPEG/PNG markers)", "ok": False})

                    # If still no text, try raw decode
                    if not result["text"]:
                        try:
                            decoded_text = decompressed.decode("utf-8", errors="ignore")
                            printable = "".join(c for c in decoded_text if c.isprintable() or c in "\n\r\t ")
                            if len(printable.strip()) > 10:
                                result["text"] = printable.strip()
                                steps.append({"msg": f"Fallback text: {len(result['text'])} chars", "ok": True})
                        except (UnicodeDecodeError, AttributeError):
                            pass
                    
                    # Parse Aadhaar format if text found
                    if result.get("text"):
                        aadhaar_data = parse_aadhaar_text(result["text"])
                        if aadhaar_data.get("parsed"):
                            result["aadhaar_data"] = aadhaar_data
                            steps.append({"msg": "Parsed Aadhaar data structure", "ok": True})
                        
                        # Add FULL decoded data for comparison
                        # Split by delimiter and show all fields
                        full_text = result["text"]
                        delimiter = chr(255)  # ÿ character
                        if delimiter in full_text:
                            fields = full_text.split(delimiter)
                            result["full_fields"] = fields
                            result["full_raw_text"] = full_text
                            result["field_count"] = len(fields)
                        else:
                            result["full_raw_text"] = full_text
                            result["full_fields"] = [full_text]
                            result["field_count"] = 1

                debug["success"] = extra
                return result

        except (ValueError, MemoryError, OverflowError):
            continue

    steps.append({"msg": f"All {50} decompression attempts failed", "ok": False})
    raise QRAppError("DECODE_FAIL", "Could not decode payload")


# ----------------------------
# Routes
# ----------------------------
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/decode", methods=["POST"])
def api_decode():
    try:
        file = request.files.get("file")
        if not file:
            raise QRAppError("NO_FILE", "No file uploaded")

        img = image_bytes_to_pil(file.read())
        raw = try_decode_qr(img)

        decoded = decode_payload(raw)

        return jsonify({"ok": True, "data": decoded})

    except QRAppError as e:
        return make_error(e.code, e.message, e.detail)

    except Exception as e:
        return make_error("SERVER_ERROR", "Unexpected error", str(e), 500)


@app.route("/api/decode-text", methods=["POST"])
def decode_text():
    try:
        raw = request.json.get("text", "")
        return jsonify({"ok": True, "data": decode_payload(raw)})
    except Exception as e:
        return make_error("ERROR", str(e))


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Analyze QR code and detect its type without full decode"""
    try:
        file = request.files.get("file")
        if not file:
            raise QRAppError("NO_FILE", "No file uploaded")

        img = image_bytes_to_pil(file.read())
        raw = try_decode_qr(img)

        analysis = {
            "raw_length": len(raw),
            "is_numeric": raw.isdigit(),
            "qr_type": "unknown",
            "estimated_format": "unknown",
            "preview": raw[:100] + "..." if len(raw) > 100 else raw
        }

        if raw.isdigit():
            analysis["qr_type"] = "compressed_numeric"

            # Try quick decompression to detect format
            n = int(raw)
            base_len = (n.bit_length() + 7) // 8

            for extra in range(0, 10):
                try:
                    blob = n.to_bytes(base_len + extra, "big")
                    decompressed, method = try_decompress(blob)

                    if decompressed:
                        analysis["compression_method"] = method
                        analysis["decompressed_size"] = len(decompressed)

                        # Detect format from decompressed data
                        if SEPARATOR in decompressed:
                            analysis["estimated_format"] = "custom_with_separator"
                        elif b"\xff\x4f\xff\x51" in decompressed:
                            analysis["estimated_format"] = "aadhaar_or_id_jpeg2000"
                        elif decompressed.startswith(b"<?xml"):
                            analysis["estimated_format"] = "xml"
                        elif decompressed.startswith(b"{"):
                            analysis["estimated_format"] = "json"
                        else:
                            analysis["estimated_format"] = "binary_data"

                        break
                except:
                    continue
        else:
            analysis["qr_type"] = "plain_text"
            analysis["estimated_format"] = "text"

        return jsonify({"ok": True, "analysis": analysis})

    except QRAppError as e:
        return make_error(e.code, e.message, e.detail)
    except Exception as e:
        return make_error("SERVER_ERROR", "Unexpected error", str(e), 500)


@app.route("/api/encode", methods=["POST"])
def api_encode():
    try:
        text = request.form.get("text", "")
        image_file = request.files.get("image")
        use_face_detection = request.form.get("face_detect", "true").lower() == "true"
        add_signature = request.form.get("add_signature", "true").lower() == "true"

        if not text and not image_file:
            raise QRAppError("EMPTY", "Text or image required")

        encode_info = {
            "original_text_length": len(text) if text else 0,
            "face_detected": False,
            "image_processed": False
        }

        # Build payload matching original binary format
        # Original format: [binary header/length fields] + [text] + [jpeg2000 image]
        # The binary header includes field lengths and metadata
        payload = b""

        # Encode text with proper structure using \xff delimiters
        text_bytes = b""
        if text:
            # Check if text is JSON with Aadhaar fields
            try:
                import json
                data = json.loads(text)
                if isinstance(data, dict) and any(k in data for k in ['name', 'aadhaar', 'dob', 'gender', 'district']):
                    # Build Aadhaar format with \xff delimiters
                    # Format: V5\xff3\xff[aadhaar+timestamp]\xff[name]\xff[dob]\xff[gender]\xff[guardian]\xff[district]\xff\xff[localities...]\xff[pin]\xff[po]\xff[state]\xff[more localities]\xff[mobile]\xff[email]
                    
                    import datetime
                    import random
                    
                    # Get fields with defaults
                    version = data.get('version', '5')
                    aadhaar = data.get('aadhaar', '').replace(' ', '').replace('X', '')[-4:] or '0000'
                    name = data.get('name', '')
                    dob = data.get('dob', '')
                    gender = data.get('gender', 'M')
                    mobile = data.get('mobile', '')
                    email = data.get('email', '')
                    guardian = data.get('guardian', '')
                    
                    # Address components (new format)
                    locality = data.get('locality', '')
                    po = data.get('po', '')
                    subDist = data.get('subDist', '')
                    district = data.get('district', '')
                    state = data.get('state', '')
                    pin = data.get('pin', '')
                    
                    # Timestamp
                    now = datetime.datetime.now()
                    timestamp = now.strftime('%Y%m%d%H%M')
                    ref_num = data.get('ref', str(random.randint(10000, 99999)))
                    
                    # Build aadhaar+timestamp field
                    aadhaar_ts_ref = f"{aadhaar}{timestamp}{ref_num}"
                    
                    # Build fields list matching original Aadhaar format
                    # Original order from real Aadhaar QR:
                    # 0: V5, 1: 3, 2: aadhaar+ts+ref, 3: name, 4: dob, 5: gender
                    # 6: guardian, 7: district, 8: '', 9: locality, 10: sub-dist
                    # 11: pin, 12: PO, 13: state, 14: locality, 15: '', 16: village alias
                    # 17: mobile, 18: email
                    
                    DELIM = chr(255)  # \xff delimiter
                    
                    # Build village alias (locality + alias if available)
                    village_alias = data.get('villageAlias', '') or locality
                    
                    fields = [
                        f"V{version}",      # 0: Version
                        "3",                # 1: Sub-version
                        aadhaar_ts_ref,     # 2: Aadhaar + timestamp + ref
                        name,               # 3: Name
                        dob,                # 4: DOB
                        gender,             # 5: Gender
                        guardian,           # 6: Guardian (C/O, S/O, etc.)
                        district,           # 7: District
                        "",                 # 8: Empty field
                        locality,           # 9: Locality/Village
                        subDist or locality,# 10: Sub-district/Tehsil
                        pin,                # 11: PIN code
                        po or locality,     # 12: Post Office
                        state,              # 13: State
                        locality,           # 14: Locality repeat
                        "",                 # 15: Empty field
                        village_alias,      # 16: Village/Town with alias
                    ]
                    
                    # Add mobile and email
                    if mobile:
                        fields.append(mobile)
                    if email:
                        fields.append(email)
                    
                    # Join with \xff delimiter and encode as latin-1 (preserves byte 255)
                    # Add trailing delimiter to match original format
                    text_str = DELIM.join(fields) + DELIM
                    text_bytes = text_str.encode('latin-1')

                    encode_info["format"] = "aadhaar_structured"
                    encode_info["field_count"] = len(fields)
                else:
                    # Regular JSON - encode as UTF-8
                    text_bytes = text.encode("utf-8")
            except (json.JSONDecodeError, ValueError):
                # Not JSON - check if pipe or newline separated Aadhaar fields
                if '|' in text:
                    # Convert pipe-separated to \xff-separated
                    DELIM = chr(255)
                    text_str = text.replace('|', DELIM)
                    text_bytes = text_str.encode('latin-1')
                    encode_info["format"] = "aadhaar_pipe"
                else:
                    # Plain text
                    text_bytes = text.encode("utf-8")

        if image_file:
            img_bytes = image_file.read()

            # Detect and crop face if enabled
            if use_face_detection:
                img_pil, face_found = detect_and_crop_face(img_bytes)
                encode_info["face_detected"] = face_found
            else:
                img_pil = Image.open(io.BytesIO(img_bytes))

            encode_info["image_processed"] = True

            # Resize to 60x60 like original
            max_size = 60
            img_pil.thumbnail((max_size, max_size), Image.LANCZOS)
            rgb_img = img_pil.convert("RGB")
            
            img_bytes = None
            j2k_success = False
            
            # Method 1: Try glymur for proper JPEG2000 (if available)
            try:
                import glymur
                import tempfile as tf

                # Save temp file and encode with glymur
                img_array = np.array(rgb_img)

                # Use secure temp file with proper cleanup
                tmp_fd, tmp_path = tempfile.mkstemp(suffix=".jp2", prefix="qr_encode_")

                try:
                    os.close(tmp_fd)  # Close the file descriptor, we'll write with glymur

                    # Create JP2 with aggressive compression (~900 bytes target for J2K codestream)
                    for cratio in [60, 55, 50, 45, 40]:
                        try:
                            # Write to JP2 file
                            jp2 = glymur.Jp2k(tmp_path, data=img_array, cratios=[cratio])

                            with open(tmp_path, 'rb') as f:
                                temp_bytes = f.read()

                            if len(temp_bytes) < 10:
                                continue

                            # Extract J2K codestream from JP2 container
                            j2k_start = temp_bytes.find(b'\xff\x4f')
                            if j2k_start >= 0:
                                j2k_bytes = temp_bytes[j2k_start:]
                                if 700 < len(j2k_bytes) < 1100:
                                    img_bytes = j2k_bytes
                                    encode_info["image_format"] = "jpeg2000"
                                    j2k_success = True
                                    break
                        except (IOError, OSError, ValueError) as e:
                            continue
                finally:
                    # Always clean up temp file
                    try:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                    except OSError:
                        pass

            except ImportError:
                pass
            except Exception:
                pass
            
            # Method 2: Try OpenCV JPEG2000
            if img_bytes is None:
                img_array = np.array(rgb_img)
                img_bgr = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)

                for compression_ratio in [250, 200, 150, 100]:
                    try:
                        encode_params = [cv2.IMWRITE_JPEG2000_COMPRESSION_X1000, compression_ratio]
                        success, encoded = cv2.imencode('.j2k', img_bgr, encode_params)
                        if success:
                            temp_bytes = encoded.tobytes()
                            if temp_bytes[:2] == b'\xff\x4f' and 700 < len(temp_bytes) < 1100:
                                img_bytes = temp_bytes
                                encode_info["image_format"] = "jpeg2000"
                                break
                    except (cv2.error, ValueError, MemoryError):
                        continue
            
            # Method 3: Pillow JPEG2000 (try multiple approaches)
            if img_bytes is None:
                # dB mode works better - lower dB = smaller file
                # Target ~900 bytes, so try low dB values first
                for db in [22, 24, 26, 28, 30]:
                    try:
                        buf = io.BytesIO()
                        rgb_img.save(buf, format="JPEG2000", quality_mode='dB',
                                   quality_layers=[db], irreversible=True)
                        temp_bytes = buf.getvalue()

                        if temp_bytes[:2] != b'\xff\x4f':
                            j2k_start = temp_bytes.find(b'\xff\x4f')
                            if j2k_start >= 0:
                                temp_bytes = temp_bytes[j2k_start:]

                        if temp_bytes[:2] == b'\xff\x4f' and 700 < len(temp_bytes) < 1100:
                            img_bytes = temp_bytes
                            encode_info["image_format"] = "jpeg2000"
                            break
                    except (IOError, OSError, ValueError, KeyError):
                        continue
            
            # Final fallback: JPEG with size matching
            if img_bytes is None:
                # Target ~900 bytes to match original
                for quality in [45, 40, 35, 30]:
                    buf = io.BytesIO()
                    rgb_img.save(buf, format="JPEG", quality=quality, optimize=True)
                    temp_bytes = buf.getvalue()
                    if 700 < len(temp_bytes) < 1100:
                        img_bytes = temp_bytes
                        encode_info["image_format"] = "jpeg"
                        break
                
                if img_bytes is None:
                    buf = io.BytesIO()
                    rgb_img.save(buf, format="JPEG", quality=35, optimize=True)
                    img_bytes = buf.getvalue()
                    encode_info["image_format"] = "jpeg"

            encode_info["processed_image_size"] = len(img_bytes)

            # Build final payload: text + image + optional signature placeholder
            # Aadhaar Secure QR V2 format:
            # [Text with 0xFF delimiters] + [JPEG2000 image] + [256-byte RSA signature]
            
            if add_signature:
                # Generate a placeholder signature (256 bytes)
                # Real Aadhaar uses RSA signature from UIDAI private key
                # We use hash-based placeholder - won't pass verification but format matches
                import hashlib
                
                # Create deterministic "signature" based on content hash
                content_hash = hashlib.sha256(text_bytes + img_bytes).digest()
                # Extend to 256 bytes (RSA-2048 signature size)
                signature_placeholder = content_hash * 8  # 32 * 8 = 256 bytes
                
                encode_info["signature_size"] = len(signature_placeholder)
                encode_info["signature_added"] = True
                
                payload = text_bytes + img_bytes + signature_placeholder
            else:
                encode_info["signature_added"] = False
                payload = text_bytes + img_bytes
        else:
            # Text only
            if add_signature:
                import hashlib
                content_hash = hashlib.sha256(text_bytes).digest()
                signature_placeholder = content_hash * 8
                payload = text_bytes + signature_placeholder
                encode_info["signature_added"] = True
            else:
                payload = text_bytes
                encode_info["signature_added"] = False

        # Compress
        compressed = gzip.compress(payload, compresslevel=9)
        encode_info["compressed_size"] = len(compressed)
        encode_info["decompressed_size"] = len(payload)

        # Convert to decimal string
        num = int.from_bytes(compressed, "big")
        decimal_str = str(num)
        encode_info["decimal_length"] = len(decimal_str)

        # Generate QR code
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(decimal_str)
        qr.make(fit=True)

        qr_img = qr.make_image(fill_color="black", back_color="white")

        buf = io.BytesIO()
        qr_img.save(buf, format="PNG")
        buf.seek(0)

        # Store encode info in session or return as header
        response = send_file(buf, mimetype="image/png")
        response.headers['X-Encode-Info'] = json.dumps(encode_info)

        return response

    except Exception as e:
        return make_error("ERROR", str(e))


@app.route("/api/verify", methods=["POST"])
def api_verify():
    """Verify that encode/decode produces the same data"""
    try:
        text = request.form.get("text", "")
        image_file = request.files.get("image")

        if not text and not image_file:
            raise QRAppError("EMPTY", "Text or image required")

        # Step 1: Encode
        payload = b""
        original_text = text
        original_image = None

        if text:
            payload += text.encode("utf-8")

        if image_file:
            img_bytes = image_file.read()
            img_pil, face_found = detect_and_crop_face(img_bytes)

            # Process image same as encode
            max_size = 80
            img_pil.thumbnail((max_size, max_size), Image.LANCZOS)
            buf = io.BytesIO()
            img_pil.convert("RGB").save(buf, format="JPEG", quality=60)
            img_bytes = buf.getvalue()

            original_image = base64.b64encode(img_bytes).decode()

            if text:
                payload += SEPARATOR
            payload += img_bytes

        # Compress
        compressed = gzip.compress(payload, compresslevel=9)
        num = int.from_bytes(compressed, "big")
        decimal_str = str(num)

        # Step 2: Decode back
        decoded = decode_payload(decimal_str)

        # Step 3: Compare
        verification = {
            "passed": True,
            "text_match": False,
            "image_match": False,
            "original_text": original_text,
            "decoded_text": decoded.get("text"),
            "original_image_size": len(original_image) if original_image else 0,
            "decoded_image_size": len(decoded.get("image_base64", ""))
        }

        # Check text
        if original_text and decoded.get("text"):
            verification["text_match"] = original_text == decoded["text"]
        elif not original_text and not decoded.get("text"):
            verification["text_match"] = True

        # Check image
        if original_image and decoded.get("image_base64"):
            # Images won't match exactly due to compression, but sizes should be close
            size_diff = abs(len(original_image) - len(decoded["image_base64"]))
            verification["image_match"] = size_diff < len(original_image) * 0.1  # Within 10%
            verification["image_size_difference"] = size_diff
        elif not original_image and not decoded.get("image_base64"):
            verification["image_match"] = True

        verification["passed"] = verification["text_match"] and verification["image_match"]

        return jsonify({"ok": True, "verification": verification})

    except Exception as e:
        return make_error("ERROR", str(e))


# ----------------------------
# Run
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True)